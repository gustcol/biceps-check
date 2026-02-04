"""
Bicep file parser implementation.

This module provides the core parsing functionality for Azure Bicep files,
converting them into structured data for security analysis.
"""

import re
from pathlib import Path
from typing import Any, Optional

import structlog

from biceps_check.parser.models import (
    BicepFile,
    BicepModule,
    BicepOutput,
    BicepParameter,
    BicepResource,
    BicepVariable,
)

logger = structlog.get_logger()


class BicepParser:
    """Parser for Azure Bicep files.

    This parser extracts resources, parameters, variables, and other
    declarations from Bicep files for security analysis.
    """

    # Regex patterns for Bicep syntax
    RESOURCE_PATTERN = re.compile(
        r"resource\s+(\w+)\s+'([^']+)'\s*=\s*(\{|\[)",
        re.MULTILINE,
    )
    PARAMETER_PATTERN = re.compile(
        r"@?(\w+)?\s*param\s+(\w+)\s+(\w+)(?:\s*=\s*(.+))?",
        re.MULTILINE,
    )
    VARIABLE_PATTERN = re.compile(
        r"var\s+(\w+)\s*=\s*(.+)",
        re.MULTILINE,
    )
    MODULE_PATTERN = re.compile(
        r"module\s+(\w+)\s+'([^']+)'\s*=\s*\{",
        re.MULTILINE,
    )
    OUTPUT_PATTERN = re.compile(
        r"output\s+(\w+)\s+(\w+)\s*=\s*(.+)",
        re.MULTILINE,
    )
    TARGET_SCOPE_PATTERN = re.compile(
        r"targetScope\s*=\s*'(\w+)'",
        re.MULTILINE,
    )
    SUPPRESSION_PATTERN = re.compile(
        r"//\s*biceps-check:disable(?:-next-line)?=([^\s]+)(?:\s+reason=\"([^\"]+)\")?",
        re.MULTILINE,
    )

    def __init__(self) -> None:
        """Initialize the parser."""
        self._parameter_values: dict[str, Any] = {}

    def parse_file(
        self,
        file_path: Path,
        parameter_file: Optional[Path] = None,
    ) -> BicepFile:
        """Parse a Bicep file.

        Args:
            file_path: Path to the Bicep file.
            parameter_file: Optional path to a parameter file.

        Returns:
            BicepFile containing parsed contents.
        """
        logger.debug("Parsing Bicep file", path=str(file_path))

        content = file_path.read_text(encoding="utf-8")

        # Load parameter values if provided
        if parameter_file and parameter_file.exists():
            self._load_parameter_file(parameter_file)

        bicep_file = BicepFile(path=file_path)

        # Parse target scope
        bicep_file.target_scope = self._parse_target_scope(content)

        # Extract suppressions first (they affect resource parsing)
        suppressions = self._extract_suppressions(content)

        # Parse declarations
        bicep_file.parameters = self._parse_parameters(content)
        bicep_file.variables = self._parse_variables(content)
        bicep_file.resources = self._parse_resources(content, suppressions)
        bicep_file.modules = self._parse_modules(content)
        bicep_file.outputs = self._parse_outputs(content)

        logger.debug(
            "Parsed Bicep file",
            path=str(file_path),
            resources=len(bicep_file.resources),
            parameters=len(bicep_file.parameters),
            variables=len(bicep_file.variables),
        )

        return bicep_file

    def _parse_target_scope(self, content: str) -> str:
        """Parse the target scope declaration.

        Args:
            content: File content.

        Returns:
            Target scope (defaults to "resourceGroup").
        """
        match = self.TARGET_SCOPE_PATTERN.search(content)
        if match:
            return match.group(1)
        return "resourceGroup"

    def _extract_suppressions(self, content: str) -> dict[int, list[str]]:
        """Extract suppression comments and their line numbers.

        Args:
            content: File content.

        Returns:
            Dictionary mapping line numbers to suppressed rule IDs.
        """
        suppressions: dict[int, list[str]] = {}
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            match = self.SUPPRESSION_PATTERN.search(line)
            if match:
                rule_ids = match.group(1).split(",")
                # Check if it's a next-line suppression
                if "next-line" in line:
                    target_line = i + 1
                else:
                    target_line = i
                suppressions.setdefault(target_line, []).extend(rule_ids)

        return suppressions

    def _parse_parameters(self, content: str) -> list[BicepParameter]:
        """Parse parameter declarations.

        Args:
            content: File content.

        Returns:
            List of parsed parameters.
        """
        parameters = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            match = self.PARAMETER_PATTERN.search(line)
            if match:
                decorator = match.group(1)
                name = match.group(2)
                param_type = match.group(3)
                default = match.group(4)

                param = BicepParameter(
                    name=name,
                    type=param_type,
                    default_value=self._parse_value(default) if default else None,
                    line_number=i,
                    secure=decorator == "secure" if decorator else False,
                )
                parameters.append(param)

        return parameters

    def _parse_variables(self, content: str) -> list[BicepVariable]:
        """Parse variable declarations.

        Args:
            content: File content.

        Returns:
            List of parsed variables.
        """
        variables = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            match = self.VARIABLE_PATTERN.search(line)
            if match:
                name = match.group(1)
                value = match.group(2)

                var = BicepVariable(
                    name=name,
                    value=self._parse_value(value),
                    line_number=i,
                )
                variables.append(var)

        return variables

    def _parse_resources(
        self,
        content: str,
        suppressions: dict[int, list[str]],
    ) -> list[BicepResource]:
        """Parse resource declarations.

        Args:
            content: File content.
            suppressions: Line number to suppression mapping.

        Returns:
            List of parsed resources.
        """
        resources = []

        for match in self.RESOURCE_PATTERN.finditer(content):
            name = match.group(1)
            type_version = match.group(2)
            start_pos = match.start()

            # Calculate line number
            line_number = content[:start_pos].count("\n") + 1

            # Parse resource type and API version
            resource_type, api_version = self._parse_type_version(type_version)

            # Extract resource body
            body_start = match.end() - 1
            body = self._extract_block(content, body_start)

            # Parse properties from body
            properties = self._parse_resource_body(body)

            # Get suppressions for this resource
            resource_suppressions = suppressions.get(line_number, [])
            # Also check line above for inline suppressions
            resource_suppressions.extend(suppressions.get(line_number - 1, []))

            resource = BicepResource(
                name=name,
                resource_type=resource_type,
                api_version=api_version,
                properties=properties,
                location=properties.get("location", ""),
                tags=properties.get("tags", {}),
                line_number=line_number,
                raw_content=body,
                suppressions=resource_suppressions,
            )
            resources.append(resource)

        return resources

    def _parse_modules(self, content: str) -> list[BicepModule]:
        """Parse module references.

        Args:
            content: File content.

        Returns:
            List of parsed modules.
        """
        modules = []

        for match in self.MODULE_PATTERN.finditer(content):
            name = match.group(1)
            source = match.group(2)
            start_pos = match.start()
            line_number = content[:start_pos].count("\n") + 1

            module = BicepModule(
                name=name,
                source=source,
                line_number=line_number,
            )
            modules.append(module)

        return modules

    def _parse_outputs(self, content: str) -> list[BicepOutput]:
        """Parse output declarations.

        Args:
            content: File content.

        Returns:
            List of parsed outputs.
        """
        outputs = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            match = self.OUTPUT_PATTERN.search(line)
            if match:
                name = match.group(1)
                output_type = match.group(2)
                value = match.group(3)

                output = BicepOutput(
                    name=name,
                    type=output_type,
                    value=self._parse_value(value),
                    line_number=i,
                )
                outputs.append(output)

        return outputs

    def _parse_type_version(self, type_version: str) -> tuple[str, str]:
        """Parse resource type and API version from type string.

        Args:
            type_version: Combined type@version string.

        Returns:
            Tuple of (resource_type, api_version).
        """
        if "@" in type_version:
            parts = type_version.split("@")
            return parts[0], parts[1]
        return type_version, ""

    def _extract_block(self, content: str, start: int) -> str:
        """Extract a balanced block (braces or brackets).

        Args:
            content: File content.
            start: Starting position (at the opening brace/bracket).

        Returns:
            The block content including delimiters.
        """
        opener = content[start]
        closer = "}" if opener == "{" else "]"

        depth = 0
        in_string = False
        escape_next = False
        end = start

        for i in range(start, len(content)):
            char = content[i]

            if escape_next:
                escape_next = False
                continue

            if char == "\\":
                escape_next = True
                continue

            if char == "'" and not in_string:
                in_string = True
            elif char == "'" and in_string:
                in_string = False
            elif not in_string:
                if char == opener:
                    depth += 1
                elif char == closer:
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break

        return content[start:end]

    def _parse_resource_body(self, body: str) -> dict[str, Any]:
        """Parse the body of a resource into properties.

        This is a simplified parser that extracts key-value pairs.
        A full implementation would handle nested structures properly.

        Args:
            body: Resource body content.

        Returns:
            Dictionary of properties.
        """
        # For now, return a simplified parse
        # A full implementation would use a proper Bicep AST parser
        properties: dict[str, Any] = {}

        # Extract properties block if present
        props_match = re.search(r"properties\s*:\s*\{", body)
        if props_match:
            props_start = props_match.end() - 1
            props_body = self._extract_block(body, props_start)
            properties["properties"] = self._parse_object(props_body)

        # Extract other top-level properties
        for key in ["name", "location", "sku", "kind", "identity", "tags"]:
            key_match = re.search(rf"{key}\s*:\s*", body)
            if key_match:
                value_start = key_match.end()
                # Find the value
                if body[value_start] in "{[":
                    value = self._extract_block(body, value_start)
                    properties[key] = self._parse_object(value) if value.startswith("{") else self._parse_array(value)
                else:
                    # Simple value - find end of line or comma
                    end = body.find("\n", value_start)
                    if end == -1:
                        end = len(body)
                    value = body[value_start:end].strip().rstrip(",")
                    properties[key] = self._parse_value(value)

        return properties

    def _parse_object(self, body: str) -> dict[str, Any]:
        """Parse an object literal.

        Args:
            body: Object body including braces.

        Returns:
            Parsed dictionary.
        """
        result: dict[str, Any] = {}

        # Remove outer braces
        inner = body.strip()
        if inner.startswith("{"):
            inner = inner[1:]
        if inner.endswith("}"):
            inner = inner[:-1]

        # Parse key-value pairs
        # Pattern: key: value or key: { ... } or key: [ ... ]
        key_pattern = re.compile(r"(\w+)\s*:\s*", re.MULTILINE)

        pos = 0
        while pos < len(inner):
            # Skip whitespace and comments
            while pos < len(inner) and inner[pos] in " \t\n\r":
                pos += 1
            if pos >= len(inner):
                break

            # Skip comments
            if inner[pos:pos + 2] == "//":
                newline = inner.find("\n", pos)
                pos = newline + 1 if newline != -1 else len(inner)
                continue

            # Find key
            key_match = key_pattern.match(inner, pos)
            if not key_match:
                pos += 1
                continue

            key = key_match.group(1)
            value_start = key_match.end()

            # Skip whitespace after colon
            while value_start < len(inner) and inner[value_start] in " \t":
                value_start += 1

            if value_start >= len(inner):
                break

            # Determine value type and extract
            if inner[value_start] == "{":
                # Nested object
                value_body = self._extract_block(inner, value_start)
                result[key] = self._parse_object(value_body)
                pos = value_start + len(value_body)
            elif inner[value_start] == "[":
                # Array
                value_body = self._extract_block(inner, value_start)
                result[key] = self._parse_array(value_body)
                pos = value_start + len(value_body)
            else:
                # Simple value - find end (newline or next key)
                value_end = value_start
                in_string = False
                while value_end < len(inner):
                    char = inner[value_end]
                    if char == "'" and (value_end == 0 or inner[value_end - 1] != "\\"):
                        in_string = not in_string
                    elif not in_string:
                        if char == "\n":
                            break
                        # Check if we hit the start of a new key
                        if char in " \t" and value_end + 1 < len(inner):
                            rest = inner[value_end:].lstrip()
                            if rest and re.match(r"\w+\s*:", rest):
                                break
                    value_end += 1

                value_str = inner[value_start:value_end].strip().rstrip(",")
                result[key] = self._parse_value(value_str)
                pos = value_end

        return result

    def _parse_array(self, body: str) -> list[Any]:
        """Parse an array literal.

        Args:
            body: Array body including brackets.

        Returns:
            Parsed list.
        """
        result: list[Any] = []

        # Remove outer brackets
        inner = body.strip()
        if inner.startswith("["):
            inner = inner[1:]
        if inner.endswith("]"):
            inner = inner[:-1]

        pos = 0
        while pos < len(inner):
            # Skip whitespace
            while pos < len(inner) and inner[pos] in " \t\n\r":
                pos += 1
            if pos >= len(inner):
                break

            # Skip comments
            if inner[pos:pos + 2] == "//":
                newline = inner.find("\n", pos)
                pos = newline + 1 if newline != -1 else len(inner)
                continue

            if inner[pos] == "{":
                # Object element
                value_body = self._extract_block(inner, pos)
                result.append(self._parse_object(value_body))
                pos += len(value_body)
            elif inner[pos] == "[":
                # Nested array
                value_body = self._extract_block(inner, pos)
                result.append(self._parse_array(value_body))
                pos += len(value_body)
            else:
                # Simple value
                value_end = pos
                in_string = False
                while value_end < len(inner):
                    char = inner[value_end]
                    if char == "'" and (value_end == 0 or inner[value_end - 1] != "\\"):
                        in_string = not in_string
                    elif not in_string and char in ",\n":
                        break
                    value_end += 1

                value_str = inner[pos:value_end].strip().rstrip(",")
                if value_str:
                    result.append(self._parse_value(value_str))
                pos = value_end + 1

        return result

    def _parse_value(self, value: str) -> Any:
        """Parse a value literal.

        Args:
            value: Value string.

        Returns:
            Parsed value.
        """
        if value is None:
            return None

        value = value.strip()

        # Boolean
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False

        # String (quoted)
        if value.startswith("'") and value.endswith("'"):
            return value[1:-1]

        # Number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        # Reference or expression
        return value

    def _load_parameter_file(self, path: Path) -> None:
        """Load parameter values from a file.

        Args:
            path: Path to parameter file (JSON or Bicep param file).
        """
        # TODO: Implement parameter file loading
        logger.debug("Parameter file loading not yet implemented", path=str(path))

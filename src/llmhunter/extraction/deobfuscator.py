"""JS deobfuscation / beautification before key extraction."""

import logging
import re

import jsbeautifier

logger = logging.getLogger("llmhunter")


class Deobfuscator:
    """Beautifies minified JS only when split/obfuscated keys are suspected."""

    def __init__(self, markers: tuple[str, ...] = ("AIzaSy",)):
        self.opts = jsbeautifier.default_options()
        self.opts.indent_size = 2
        self.opts.preserve_newlines = True
        self.opts.max_preserve_newlines = 2
        self.opts.wrap_line_length = 0

        self._split_hints: list[re.Pattern[str]] = []
        self._full_key_res: list[re.Pattern[str]] = []
        for marker in markers:
            escaped = re.escape(marker)
            self._split_hints.append(re.compile(rf"""["']{escaped}["']"""))
            self._full_key_res.append(re.compile(rf"{escaped}[a-zA-Z0-9_-]{{20,}}"))

    def process(self, content: str) -> str:
        if not content:
            return content

        has_split_hint = any(p.search(content) for p in self._split_hints)
        has_full_key = any(p.search(content) for p in self._full_key_res)

        if has_split_hint and not has_full_key:
            try:
                return jsbeautifier.beautify(content, self.opts)
            except Exception as e:
                logger.debug(f"Beautification failed: {e}")

        return content

"""Shared visual language for Capri's Textual terminal screens."""
from rich.text import Text
from textual.widgets import Input

CSS = """
App {
    background: ansi_default;
}

Screen {
    background: ansi_default;
    color: ansi_default;
}

Header, Footer, Button, RichLog {
    background: ansi_default;
}

Header {
    color: ansi_bright_cyan;
    text-style: bold;
}

Footer {
    color: ansi_bright_black;
}

Static#brand, Static#screen-title {
    color: ansi_bright_cyan;
    text-style: bold;
}

Static#step-count, Static#status {
    color: ansi_bright_green;
}

Static#error {
    color: ansi_bright_red;
}

Button {
    width: 12;
    min-width: 12;
    height: 3;
    margin-left: 1;
    border: round ansi_bright_cyan;
    background: ansi_default;
    color: ansi_bright_white;
    content-align: center middle;
}

Button:focus {
    border: round ansi_bright_green;
    color: ansi_bright_white;
    text-style: bold;
}

Button.-primary {
    color: ansi_bright_cyan;
    background: ansi_default;
    border: round ansi_bright_cyan;
    text-style: bold;
}

Button:disabled {
    color: ansi_bright_white;
    background: ansi_default;
    border: round ansi_bright_cyan;
}

Input, Select, Select > SelectOverlay, SelectOverlay > OptionList {
    background: ansi_default;
}

Input, Select {
    margin-bottom: 1;
}
"""


class AsteriskInput(Input):
    """Textual password input that shows one star per character."""

    @property
    def _value(self):
        if self.password:
            # Textual 8.2.8 renders its built-in password mask with a replacement glyph.
            return Text("*" * len(self.value), no_wrap=True, overflow="ignore", end="")
        return super()._value

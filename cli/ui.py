from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, Footer, Header, RichLog, Static

from cli.theme import CSS as THEME_CSS


class RunApp(App):
    """Run the engagement in a worker while keeping progress visible and scrollable."""

    BINDINGS = [Binding("q", "exit_app", "Exit"), Binding("escape", "exit_app", "Exit")]

    CSS = THEME_CSS + """
    #screen-title {
        margin: 0 2;
    }

    #run-status {
        margin: 0 2;
    }

    #run-log {
        height: 1fr;
        margin: 1 2;
    }

    #nav {
        dock: bottom;
        height: 4;
        align-horizontal: right;
        margin-top: 1;
        padding-right: 2;
    }
    """

    def __init__(self):
        super().__init__(ansi_color=True)
        self.title = "CAPRI"
        self.complete = False
        self.exit_code = 1

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("CAPRI  /  RUN ENGAGEMENT", id="screen-title")
        yield Static("Validating the sandbox before active probes.", id="run-status")
        yield RichLog(id="run-log", wrap=True, markup=False, highlight=False)
        with Horizontal(id="nav"):
            yield Button("Exit", id="exit", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#run-log", RichLog).write(Text("Starting engagement…", style="bright_cyan"))
        self.run_worker(self._execute, thread=True, exclusive=True)

    def _execute(self) -> None:
        from tools import run_engagement

        try:
            self.exit_code = run_engagement.main(progress=self._emit)
            message = "Engagement finished. Review the output above."
        except Exception as error:
            self.exit_code = 1
            message = f"Engagement failed: {error}"
        self.call_from_thread(self._finish, message)

    def _emit(self, message: str) -> None:
        self.call_from_thread(self._append, message)

    def _append(self, message: str) -> None:
        style = "bright_red" if any(word in message.lower() for word in
                                     ("failed", "invalid", "aborting", "error")) else None
        self.query_one("#run-log", RichLog).write(Text(message, style=style))

    def _finish(self, message: str) -> None:
        self.complete = True
        style = "bold bright_green" if self.exit_code == 0 else "bold bright_red"
        self.query_one("#run-status", Static).update(Text(message, style=style))
        self.query_one("#exit", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "exit" and self.complete:
            self.exit(self.exit_code)

    def action_exit_app(self) -> None:
        if self.complete:
            self.exit(self.exit_code)

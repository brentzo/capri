from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.events import Resize
from textual.widgets import Button, Footer, Header, Input, OptionList, Select, Static

from cli import terminal
from cli.setup import _launch, model_choices
from cli.theme import AsteriskInput, CSS as THEME_CSS
from tools import catalog, modelplane

STEP_LABELS = ("Operator model", "Operator API key", "Verifier model",
               "Verifier API key", "Review and start")


class SetupApp(App):
    """Stable layout; only the active step controls change as the user navigates."""

    CSS = THEME_CSS + """
    #wordmark {
        height: 6;
        margin: 0 2;
        color: ansi_bright_cyan;
        text-style: bold;
    }

    #screen-title {
        margin: 0 2 0 3;
    }

    #step-count {
        margin: 0 2 0 3;
    }

    #role-summary {
        height: 2;
        margin: 1 2 0 3;
    }

    #prompt {
        margin: 1 2 1 3;
        text-style: bold;
    }

    #search, #model, #model-results, #custom-model, #api-key, #review {
        margin-left: 2;
        margin-right: 2;
    }

    #search {
        height: 2;
        border: none;
        border-bottom: tall ansi_bright_cyan;
        padding: 0 1;
        color: ansi_bright_white;
    }

    SelectCurrent {
        border: tall ansi_bright_cyan;
        background: ansi_default;
        color: ansi_bright_white;
        padding: 0 1;
    }

    #model-results {
        display: none;
        height: auto;
        max-height: 8;
        margin: 1 2 0 2;
        padding: 0 1;
        border: tall ansi_bright_cyan;
        background: ansi_default;
        color: ansi_bright_white;
    }

    #model {
        margin: 1 2 0 2;
    }

    #search, #custom-model, #api-key, #review {
        display: none;
    }

    #review {
        height: auto;
        color: ansi_default;
    }

    #launch-status, #error {
        margin: 0 2;
        height: auto;
    }

    #nav {
        dock: bottom;
        height: 4;
        align-horizontal: right;
        margin-top: 1;
        padding-right: 2;
    }

    #back {
        margin-left: 0;
    }
    """

    def __init__(self, args):
        super().__init__(ansi_color=True)
        self.title = "CAPRI"
        self.args = args
        self.step = 0
        self.result = None
        self.starting = False
        self.all_choices = []
        self.choices = []
        self.state = {
            "operator": {"provider": None, "model": None, "key": ""},
            "verifier": {"provider": None, "model": None, "key": ""},
        }
        self.saved_env = modelplane.load_env(modelplane.state_dir(args))

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(terminal.ART, id="wordmark")
        yield Static("MODEL SETUP", id="screen-title")
        yield Static("", id="step-count")
        yield Static("", id="role-summary")
        yield Static("", id="prompt")
        yield Input(placeholder="Search, then press Enter to choose", id="search")
        yield OptionList(id="model-results", markup=False)
        yield Select([], allow_blank=True, prompt="Choose a provider and model", id="model")
        yield Input(placeholder="Or type a model ID", id="custom-model")
        yield AsteriskInput(placeholder="API key (input is masked)", password=True, id="api-key")
        yield Static("", id="review")
        yield Static("", id="launch-status")
        yield Static("", id="error")
        with Horizontal(id="nav"):
            yield Button("Back", id="back")
            yield Button("Next", id="next", variant="primary")
            yield Button("Quit", id="quit")
        yield Footer()

    def on_mount(self) -> None:
        self._show_step()
        self._update_wordmark(self.size)

    def on_resize(self, event: Resize) -> None:
        self._update_wordmark(event.size)

    def _update_wordmark(self, size) -> None:
        compact = size.width < 48 or size.height < 18
        self.query_one("#wordmark", Static).display = not compact and size.height >= 22
        self.query_one("#prompt", Static).display = not compact

    @on(Select.Changed, "#model")
    def _on_model_changed(self, event: Select.Changed) -> None:
        custom = self.query_one("#custom-model", Input)
        custom.display = (isinstance(event.value, int)
                          and self.choices[event.value][1] is None)
        if custom.display and self.focused is self.query_one("#model", Select):
            custom.focus()

    @on(Input.Changed, "#search")
    def _on_search_changed(self, event: Input.Changed) -> None:
        if self.step not in (0, 2):
            return
        select = self.query_one("#model", Select)
        results = self.query_one("#model-results", OptionList)
        current = (self.choices[select.value]
                   if isinstance(select.value, int) and select.value < len(self.choices)
                   else None)
        query = event.value.casefold().strip()
        self.choices = [
            choice for choice in self.all_choices
            if query in f"{catalog.label(choice[0])} {choice[1] or 'type a model ID'}".casefold()
        ]
        select.set_options(self._options())
        select.prompt = "No matching providers or models" if not self.choices else "Choose a provider and model"
        results.clear_options()
        if query and self.choices:
            results.add_options([label for label, _ in self._options()])
        results.display = bool(query and self.choices)
        select.display = not results.display
        selected = next((index for index, choice in enumerate(self.choices)
                         if choice == current), None)
        select.value = selected if selected is not None else Select.NULL

    @on(Input.Submitted, "#search")
    def _on_search_submitted(self) -> None:
        if not self.choices:
            self._show_error("No matching providers or models.")
        elif len(self.choices) == 1:
            self._select_search_result(0)
        else:
            results = self.query_one("#model-results", OptionList)
            results.focus()
            results.action_first()

    @on(OptionList.OptionSelected, "#model-results")
    def _on_model_result_selected(self, event: OptionList.OptionSelected) -> None:
        self._select_search_result(event.option_index)

    def _select_search_result(self, index: int) -> None:
        select = self.query_one("#model", Select)
        select.value = index
        select.display = True
        self.query_one("#model-results", OptionList).display = False
        self.query_one("#search", Input).value = ""
        select.focus()

    @on(Button.Pressed)
    def _on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.exit()
        elif event.button.id == "back":
            self._save_current()
            if self.step > 0:
                if self.step in (0, 2):
                    self.query_one("#search", Input).value = ""
                self.step -= 1
                self._show_step()
        elif event.button.id == "next":
            if self.result is not None:
                self.exit(self.result)
            elif self.step == len(STEP_LABELS) - 1:
                self._start_gateway()
            elif self._save_current():
                if self.step in (0, 2):
                    self.query_one("#search", Input).value = ""
                self.step += 1
                self._show_step()

    def _role_for_step(self):
        return "operator" if self.step < 2 else "verifier"

    def _options(self):
        return [(f"{catalog.label(provider)}  /  {model or 'type a model ID'}", index)
                for index, (provider, model) in enumerate(self.choices)]

    def _show_step(self):
        role = self._role_for_step()
        is_model = self.step in (0, 2)
        is_key = self.step in (1, 3)
        is_review = self.step == 4
        self.query_one("#step-count", Static).update(self._progress_text())
        self.query_one("#role-summary", Static).update(self._role_text())
        self.query_one("#error", Static).update("")
        self.query_one("#launch-status", Static).update("")
        self.query_one("#prompt", Static).update(self._prompt(role))
        search = self.query_one("#search", Input)
        model_select = self.query_one("#model", Select)
        model_input = self.query_one("#custom-model", Input)
        key_input = self.query_one("#api-key", AsteriskInput)
        review = self.query_one("#review", Static)
        search.display = is_model
        model_select.display = is_model
        self.query_one("#model-results", OptionList).display = False
        model_input.display = False
        key_input.display = is_key
        review.display = is_review

        if is_model:
            saved = self.state[role]
            excluded = self.state["operator"]["provider"] if role == "verifier" else None
            self.all_choices = model_choices(excluded)
            self.choices = self.all_choices[:]
            model_select.set_options(self._options())
            model_select.prompt = "Choose a provider and model"
            selected = next((index for index, (provider, model) in enumerate(self.choices)
                             if provider == saved["provider"]
                             and ((model == saved["model"]) or (model is None and
                                  saved["model"] not in catalog.models(provider)))), None)
            model_select.value = selected if selected is not None else Select.NULL
            model_input.value = saved["model"] if selected is not None and self.choices[selected][1] is None else ""
            model_input.display = (selected is not None and self.choices[selected][1] is None)
        elif is_key:
            key_input.value = self.state[role]["key"]
        elif is_review:
            review.update(self._review_text())

        self.query_one("#back", Button).disabled = self.step == 0 or self.starting
        next_button = self.query_one("#next", Button)
        next_button.label = "Start" if is_review else "Next"
        next_button.disabled = self.starting
        if is_model:
            search.focus()
        elif is_key:
            key_input.focus()
        elif is_review:
            next_button.focus()

    def _prompt(self, role):
        if self.step in (0, 2):
            return (f"Choose the {role.title()} model" if role == "operator" else
                    f"Choose the Verifier model (not {catalog.label(self.state['operator']['provider'])})")
        if self.step in (1, 3):
            provider = self.state[role]["provider"]
            return f"Enter the {catalog.label(provider)} API key for {role.title()}"
        return "Review the provider pairing before starting Bifrost."

    def _progress_text(self):
        text = Text()
        for index in range(len(STEP_LABELS)):
            text.append("● " if index < self.step else "○ ",
                        style="bright_cyan" if index <= self.step else "bright_black")
        text.append(f"  STEP {self.step + 1} OF {len(STEP_LABELS)}  /  {STEP_LABELS[self.step]}",
                    style="bold")
        return text

    def _role_text(self):
        text = Text()
        for index, role in enumerate(("operator", "verifier")):
            if index:
                text.append("\n")
            current = self.state[role]
            label = (f"{catalog.label(current['provider'])} / {current['model']}"
                     if current["provider"] else "not selected")
            text.append(f"{role.title():8} ", style="bold bright_cyan")
            text.append(label)
        return text

    def _review_text(self):
        text = Text()
        for role in ("operator", "verifier"):
            current = self.state[role]
            configured = bool(current["key"] or self.saved_env.get(catalog.key_env(current["provider"])))
            text.append(f"{role.title()}  ", style="bold bright_cyan")
            text.append(f"{catalog.label(current['provider'])} / {current['model']}\n")
            text.append("  API key  ", style="bold")
            text.append("********  configured\n" if configured else "not configured\n",
                        style="bright_green" if configured else "bright_red")
        text.append("\nOperator and Verifier providers are different.", style="bold bright_green")
        return text

    def _save_current(self):
        if self.step in (0, 2):
            select = self.query_one("#model", Select)
            if select.is_blank():
                self._show_error("Choose a model before continuing.")
                return False
            provider, model = self.choices[select.value]
            if model is None:
                model = self.query_one("#custom-model", Input).value.strip()
                if not model:
                    self._show_error("Type a model ID before continuing.")
                    return False
            role = self._role_for_step()
            current = self.state[role]
            if current["provider"] != provider:
                current["key"] = ""
            current.update(provider=provider, model=model)
        elif self.step in (1, 3):
            role = self._role_for_step()
            current = self.state[role]
            key = self.query_one("#api-key", AsteriskInput).value.strip()
            if not key and not self.saved_env.get(catalog.key_env(current["provider"]), "").strip():
                self._show_error("Enter the provider API key to continue.")
                return False
            current["key"] = key
        self.query_one("#role-summary", Static).update(self._role_text())
        return True

    def _show_error(self, message):
        self.query_one("#error", Static).update(Text(message, style="bold bright_red"))

    def _start_gateway(self):
        self.starting = True
        self.query_one("#back", Button).disabled = True
        self.query_one("#next", Button).disabled = True
        self.query_one("#quit", Button).disabled = True
        self.query_one("#launch-status", Static).update("Starting Bifrost gateway…")
        self.run_worker(self._launch_gateway, thread=True, exclusive=True)

    def _launch_gateway(self):
        operator, verifier = self.state["operator"], self.state["verifier"]
        keys = {
            catalog.key_env(operator["provider"]): operator["key"],
            catalog.key_env(verifier["provider"]): verifier["key"],
        }

        def progress(message):
            self.call_from_thread(self._set_launch_status, message)

        try:
            result = _launch(self.args, (operator["provider"], operator["model"]),
                             (verifier["provider"], verifier["model"]), keys, progress)
        except Exception as error:
            result = {"ok": False, "error": str(error)}
        self.call_from_thread(self._finish_launch, result)

    def _set_launch_status(self, message):
        self.query_one("#launch-status", Static).update(Text(f"›  {message}", style="bright_green"))

    def _finish_launch(self, result):
        self.starting = False
        self.result = result
        self.query_one("#quit", Button).disabled = False
        if result["ok"]:
            routes = result["routes"]
            self.query_one("#launch-status", Static).update(
                Text(f"Gateway healthy  ·  Operator {routes['operator']}  ·  Verifier {routes['verifier']}",
                     style="bold bright_green"))
            self.query_one("#next", Button).label = "Done"
            self.query_one("#next", Button).disabled = False
        else:
            self.result = None
            self._show_error(result["error"])
            self.query_one("#back", Button).disabled = False
            self.query_one("#next", Button).label = "Retry"
            self.query_one("#next", Button).disabled = False

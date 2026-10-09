"""Controles Tkinter para ejecutar fases nuevas o continuar resultados guardados."""

import queue
import threading
from pathlib import Path
from tkinter import Tk, StringVar, TclError, messagebox, scrolledtext, ttk

from support.interface.runner import (ROOT, SavedRun, analyze_phase, mine_phase, reporter_phase,
                              run_analysis, saved_run, visualize_phase)
from support.core.config import repository_limit


# Lee la clave sin mostrarla; la terminal solo la entrega a procesos iniciados después.
KEY_COMMAND = "read -rsp 'Clave API de OpenRouter: ' OPENROUTER_API_KEY && echo && export OPENROUTER_API_KEY"


def project_path(path: Path) -> str:
    """Muestra la ruta compartida con el anfitrión, relativa a la raíz del proyecto."""
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


class AnalysisApp:
    """Mantiene Tk en el hilo principal mientras otro hilo realiza el análisis."""

    def __init__(self, root: Tk):
        """Crea los controles y la cola que procesa el bucle de eventos de Tk."""
        # El hilo de trabajo envía eventos; solo process_events modifica los controles.
        self.root = root
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.running = False
        self.miner_run: SavedRun | None = None
        root.title("Análisis de seguridad de GitHub")
        root.minsize(760, 560)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.protocol("WM_DELETE_WINDOW", self.close)

        frame = ttk.Frame(root, padding=18)
        frame.grid(sticky="nsew")
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Análisis de seguridad", font=("TkDefaultFont", 17, "bold")).grid(
            row=0, column=0, sticky="w")
        ttk.Label(frame, text="Si la clave API no está configurada, puedes ejecutar:").grid(
            row=1, column=0, sticky="w", pady=(8, 3))
        command = ttk.Entry(frame)
        command.insert(0, KEY_COMMAND)
        command.configure(state="readonly")
        command.grid(row=2, column=0, sticky="ew")
        ttk.Label(frame, text="Luego reinicia main.py desde la misma terminal.").grid(
            row=3, column=0, sticky="w", pady=(3, 8))

        controls = ttk.Frame(frame)
        controls.grid(row=4, column=0, sticky="ew", pady=(14, 8))
        controls.columnconfigure(0, weight=1)
        ttk.Label(controls, text="Organización de GitHub").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Límite de repositorios").grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.organization = StringVar(value="nestjs")
        self.limit = StringVar(value=str(repository_limit()))
        self.organization_entry = ttk.Entry(controls, textvariable=self.organization, state="readonly")
        self.organization_entry.grid(row=1, column=0, sticky="ew")
        self.limit_entry = ttk.Entry(controls, textvariable=self.limit, width=12)
        self.limit_entry.grid(row=1, column=1, sticky="w", padx=(12, 0))

        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, sticky="w", pady=(2, 12))
        self.buttons = {}
        for column, (phase, label) in enumerate((
            ("all", "Ejecutar todo"), ("miner", "Miner"), ("analyzer", "Analyzer"),
            ("visualizer", "Visualizer"), ("reporter", "Reporter"),
        )):
            button = ttk.Button(actions, text=label, command=lambda name=phase: self.start(name))
            button.grid(row=0, column=column, padx=(0, 8))
            self.buttons[phase] = button
        ttk.Label(actions, text="Reporter revisa este proyecto y puede ejecutarse por separado.").grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))

        ttk.Label(frame, text="Ejecución actual de Miner").grid(row=6, column=0, sticky="w")
        self.refresh_button = ttk.Button(frame, text="Actualizar estado", command=self.refresh_run)
        self.refresh_button.grid(row=7, column=0, sticky="w", pady=(4, 5))
        self.run_status = StringVar(value="No hay una ejecución seleccionada.")
        ttk.Label(frame, textvariable=self.run_status).grid(row=8, column=0, sticky="w")
        ttk.Label(frame, text="Progreso por fase y repositorio").grid(row=9, column=0, sticky="w", pady=(10, 0))
        self.log = scrolledtext.ScrolledText(frame, height=15, state="disabled", wrap="word")
        self.log.grid(row=10, column=0, sticky="nsew", pady=(4, 10))
        frame.rowconfigure(10, weight=1)
        self.refresh_run()
        self.root.after(100, self.process_events)

    def refresh_run(self) -> None:
        """Consulta la única ruta activa de Miner, incluso tras reiniciar la GUI."""
        current = ROOT / "runs" / self.organization.get().lower()
        self.miner_run = saved_run(current)
        self.update_buttons()

    def update_buttons(self) -> None:
        """Habilita cada fase según los artefactos persistidos de la ejecución elegida."""
        selected = self.miner_run
        complete = selected is not None and selected.completed == selected.total
        analyzed = bool(complete and selected.analyzed)
        if selected:
            self.run_status.set(f"Miner: {selected.completed}/{selected.total} repositorios; "
                                f"Analyzer: {'listo' if selected.analyzed else 'pendiente'}; "
                                f"Visualizer: {'listo' if selected.visualized else 'pendiente'}")
        else:
            self.run_status.set("No hay una ejecución actual de Miner.")
        for phase, button in self.buttons.items():
            allowed = not self.running and (
                phase in {"all", "miner", "reporter"}
                or (phase == "analyzer" and complete)
                or (phase == "visualizer" and analyzed)
            )
            button.configure(state="normal" if allowed else "disabled")
        self.refresh_button.configure(state="disabled" if self.running else "normal")

    def append_log(self, message: str) -> None:
        """Agrega un avance al registro, que permanece de solo lectura."""
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start(self, phase: str = "all") -> None:
        """Inicia una fase en segundo plano sin bloquear Tk."""
        if self.running:
            return
        organization, limit = self.organization.get().strip(), None
        if phase in {"all", "miner"}:
            try:
                limit = int(self.limit.get().strip())
            except ValueError:
                messagebox.showerror("Límite inválido", "Ingresa un número entero positivo.")
                return
            if not 1 <= limit <= 50:
                messagebox.showerror("Límite inválido", "Ingresa un número entre 1 y 50.")
                return
            if not organization:
                messagebox.showerror("Organización inválida", "Ingresa una organización de GitHub.")
                return
        selected = self.miner_run
        if phase in {"analyzer", "visualizer"} and (
            selected is None or selected.completed != selected.total
        ):
            messagebox.showerror("Ejecución requerida", "Primero completa una ejecución de Miner.")
            return
        if phase == "visualizer" and not selected.analyzed:
            messagebox.showerror("Analyzer pendiente", "Ejecuta Analyzer antes de Visualizer.")
            return
        if phase in {"all", "miner"}:
            self.miner_run = None
        self.running = True
        self.organization_entry.configure(state="disabled")
        self.limit_entry.configure(state="disabled")
        self.update_buttons()
        if phase in {"all", "miner"}:
            target = f"{organization}, límite {limit}"
        elif phase == "reporter":
            target = "proyecto propio"
        else:
            target = str(selected.path)
        self.append_log(f"Inicio de {phase}: {target}")
        worker = threading.Thread(target=self.run_worker,
                                  args=(phase, organization, limit, selected.path if selected else None),
                                  daemon=True)
        worker.start()

    def run_worker(self, phase: str, organization: str, limit: int | None,
                   selected: Path | None) -> None:
        """Ejecuta la fase elegida fuera del hilo de Tk y devuelve eventos."""
        try:
            progress = lambda message: self.events.put(("progress", message))
            if phase == "all":
                outcome = run_analysis(organization, limit, progress,
                                       lambda path: self.events.put(("dashboard", path)))
                result = outcome.export
                if outcome.reporter_error:
                    progress(f"Reporter: no pudo terminar: {outcome.reporter_error}")
            elif phase == "miner":
                result = mine_phase(organization, limit, progress)
            elif phase == "analyzer":
                result = analyze_phase(selected, progress)
            elif phase == "visualizer":
                result = visualize_phase(selected, progress)
                self.events.put(("dashboard", result))
            elif phase == "reporter":
                result = reporter_phase(progress)
            else:
                raise ValueError("Fase desconocida")
            self.events.put(("done", (phase, result)))
        except (OSError, ValueError, RuntimeError) as error:
            self.events.put(("error", str(error)))
        except Exception as error:
            self.events.put(("error", f"Error inesperado ({type(error).__name__}); revisa la terminal"))

    def process_events(self) -> None:
        """Procesa eventos en lotes para que los avances no bloqueen Tk."""
        for _ in range(100):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "progress":
                self.append_log(str(value))
            elif kind == "dashboard":
                path = Path(value)
                if path.is_file():
                    self.append_log(f"HTML listo: {project_path(path)} (desde la raíz del proyecto).")
            elif kind == "done":
                phase, result = value
                self.append_log(f"{phase}: ejecución terminada. Resultado: {project_path(Path(result))}")
                self.finish()
                self.refresh_run()
            elif kind == "error":
                self.append_log(f"Ejecución detenida: {value}")
                self.finish()
                self.refresh_run()
        self.root.after(100, self.process_events)

    def finish(self) -> None:
        """Habilita de nuevo los controles cuando termina el trabajo."""
        self.running = False
        self.organization_entry.configure(state="readonly")
        self.limit_entry.configure(state="normal")
        self.update_buttons()

    def close(self) -> None:
        """Confirma la interrupción de una ejecución antes de cerrar la ventana."""
        if self.running and not messagebox.askyesno(
            "¿Cerrar durante el análisis?",
            "El análisis en curso se interrumpirá y podría dejar resultados parciales. ¿Cerrar de todos modos?",
        ):
            return
        self.root.destroy()


def launch() -> None:
    """Crea la ventana cuando main.py se inicia sin subcomandos."""
    try:
        root = Tk()
    except TclError as error:
        raise RuntimeError("Tkinter necesita una sesión gráfica activa en Linux (DISPLAY)") from error
    AnalysisApp(root)
    root.mainloop()

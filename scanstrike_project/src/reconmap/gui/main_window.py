from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QComboBox,
    QPlainTextEdit,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from reconmap.core.exporter import export_markdown
from reconmap.core.models import Finding, HostInfo, NextStep
from reconmap.core.parser import parse_nmap_xml
from reconmap.core.rules import build_findings_and_steps
from reconmap.core.scanner import SCAN_PROFILES, ScanPlan, Scanner, ScannerError


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ReconMap")
        self.resize(1300, 850)

        self.scanner = Scanner()
        self.process: QProcess | None = None
        self.current_plan: ScanPlan | None = None
        self.current_hosts: list[HostInfo] = []
        self.current_findings: list[Finding] = []
        self.current_steps: list[NextStep] = []

        self._setup_ui()
        self._setup_menu()

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        control_box = QGroupBox("Scan Controls")
        control_layout = QGridLayout(control_box)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Example: 10.10.10.5 or 10.10.10.0/24")

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(SCAN_PROFILES.keys())
        self.profile_combo.setCurrentText("Default Scripts + Versions")

        self.custom_args_input = QLineEdit()
        self.custom_args_input.setPlaceholderText("Optional extra args, e.g. -Pn --script vuln")

        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        control_layout.addWidget(QLabel("Target"), 0, 0)
        control_layout.addWidget(self.target_input, 0, 1, 1, 3)
        control_layout.addWidget(QLabel("Profile"), 1, 0)
        control_layout.addWidget(self.profile_combo, 1, 1)
        control_layout.addWidget(QLabel("Extra Args"), 1, 2)
        control_layout.addWidget(self.custom_args_input, 1, 3)
        control_layout.addWidget(self.start_button, 2, 2)
        control_layout.addWidget(self.stop_button, 2, 3)

        root.addWidget(control_box)

        self.tabs = QTabWidget()
        self.raw_output = QPlainTextEdit()
        self.raw_output.setReadOnly(True)

        self.hosts_table = QTableWidget(0, 5)
        self.hosts_table.setHorizontalHeaderLabels(["IP", "Hostname", "Status", "OS Guess", "Open Ports"])
        self.hosts_table.horizontalHeader().setStretchLastSection(True)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hosts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.services_table = QTableWidget(0, 7)
        self.services_table.setHorizontalHeaderLabels(["Host", "Port", "Proto", "State", "Service", "Product", "Version"])
        self.services_table.horizontalHeader().setStretchLastSection(True)
        self.services_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.services_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Host", "Port", "Title", "Details"])
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.steps_table = QTableWidget(0, 4)
        self.steps_table.setHorizontalHeaderLabels(["Host", "Port", "Service", "Suggested Action"])
        self.steps_table.horizontalHeader().setStretchLastSection(True)
        self.steps_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.steps_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.summary_text = QPlainTextEdit()
        self.summary_text.setReadOnly(True)

        self.tabs.addTab(self.raw_output, "Raw Output")
        self.tabs.addTab(self.hosts_table, "Hosts")
        self.tabs.addTab(self.services_table, "Services")
        self.tabs.addTab(self.findings_table, "Interesting Findings")
        self.tabs.addTab(self.steps_table, "Next Steps")
        self.tabs.addTab(self.summary_text, "Summary")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        root.addWidget(splitter, 1)

        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready")

    def _setup_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")

        open_xml_action = QAction("Open XML...", self)
        open_xml_action.triggered.connect(self.open_xml)
        file_menu.addAction(open_xml_action)

        export_md_action = QAction("Export Markdown...", self)
        export_md_action.triggered.connect(self.export_markdown_report)
        file_menu.addAction(export_md_action)

        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

    def start_scan(self) -> None:
        self.raw_output.clear()
        self.summary_text.clear()
        self.clear_tables()

        try:
            self.current_plan = self.scanner.build_scan_plan(
                target=self.target_input.text(),
                profile_name=self.profile_combo.currentText(),
                custom_args=self.custom_args_input.text(),
            )
        except ScannerError as exc:
            QMessageBox.critical(self, "Scan Error", str(exc))
            return

        self.process = QProcess(self)
        self.process.setProgram(self.current_plan.command[0])
        self.process.setArguments(self.current_plan.command[1:])
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self.on_process_output)
        self.process.finished.connect(self.on_scan_finished)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(f"Running: {' '.join(self.current_plan.command)}")
        self.raw_output.appendPlainText(f"$ {' '.join(self.current_plan.command)}\n")
        self.process.start()

    def stop_scan(self) -> None:
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
            self.statusBar().showMessage("Scan stopped")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def on_process_output(self) -> None:
        if not self.process:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        if data:
            self.raw_output.appendPlainText(data.rstrip())

    def on_scan_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            self.statusBar().showMessage(f"Scan ended with exit code {exit_code}")
            QMessageBox.warning(self, "Scan Finished", f"Scan ended with exit code {exit_code}.")
            return

        if not self.current_plan:
            return

        try:
            self.load_xml_results(self.current_plan.xml_path)
            self.statusBar().showMessage(f"Scan complete. Results loaded from {self.current_plan.xml_path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Parse Error", str(exc))

    def load_xml_results(self, xml_path: str | Path) -> None:
        self.current_hosts = parse_nmap_xml(xml_path)
        self.current_findings, self.current_steps = build_findings_and_steps(self.current_hosts)
        self.populate_hosts_table()
        self.populate_services_table()
        self.populate_findings_table()
        self.populate_steps_table()
        self.populate_summary()

    def populate_hosts_table(self) -> None:
        self.hosts_table.setRowCount(len(self.current_hosts))
        for row, host in enumerate(self.current_hosts):
            values = [host.ip, host.hostname, host.status, host.os_guess, str(host.port_count)]
            for col, value in enumerate(values):
                self.hosts_table.setItem(row, col, QTableWidgetItem(value))
        self.hosts_table.resizeColumnsToContents()

    def populate_services_table(self) -> None:
        service_rows = sum(len(host.open_ports) for host in self.current_hosts)
        self.services_table.setRowCount(service_rows)
        row = 0
        for host in self.current_hosts:
            for port in host.open_ports:
                values = [
                    host.ip,
                    str(port.port),
                    port.protocol,
                    port.state,
                    port.service,
                    port.product,
                    port.display_version,
                ]
                for col, value in enumerate(values):
                    self.services_table.setItem(row, col, QTableWidgetItem(value))
                row += 1
        self.services_table.resizeColumnsToContents()

    def populate_findings_table(self) -> None:
        self.findings_table.setRowCount(len(self.current_findings))
        for row, finding in enumerate(self.current_findings):
            values = [finding.severity, finding.host, finding.port, finding.title, finding.details]
            for col, value in enumerate(values):
                self.findings_table.setItem(row, col, QTableWidgetItem(value))
        self.findings_table.resizeColumnsToContents()

    def populate_steps_table(self) -> None:
        self.steps_table.setRowCount(len(self.current_steps))
        for row, step in enumerate(self.current_steps):
            values = [step.host, step.port, step.service, step.action]
            for col, value in enumerate(values):
                self.steps_table.setItem(row, col, QTableWidgetItem(value))
        self.steps_table.resizeColumnsToContents()

    def populate_summary(self) -> None:
        lines: list[str] = []
        lines.append("ReconMap Summary\n")
        if not self.current_hosts:
            lines.append("No hosts parsed.")
        for host in self.current_hosts:
            label = f"{host.ip} ({host.hostname})" if host.hostname else host.ip
            lines.append(f"Host: {label}")
            lines.append(f"Status: {host.status}")
            lines.append(f"OS Guess: {host.os_guess or 'Unknown'}")
            lines.append("Open Ports:")
            for port in host.open_ports:
                version = port.display_version or "Unknown"
                lines.append(f"  - {port.port}/{port.protocol} - {port.service or 'unknown'} - {version}")
            lines.append("")

        if self.current_findings:
            lines.append("Interesting Findings:")
            for finding in self.current_findings:
                lines.append(f"  - [{finding.severity}] {finding.host} {finding.port}: {finding.title}")
            lines.append("")

        if self.current_steps:
            lines.append("Suggested Next Steps:")
            for step in self.current_steps:
                lines.append(f"  - {step.host} {step.port} ({step.service}): {step.action}")

        self.summary_text.setPlainText("\n".join(lines))

    def open_xml(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Nmap XML", str(Path.home()), "XML Files (*.xml)")
        if not path:
            return
        try:
            self.load_xml_results(path)
            self.statusBar().showMessage(f"Loaded XML results from {path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Open XML Error", str(exc))

    def export_markdown_report(self) -> None:
        if not self.current_hosts:
            QMessageBox.information(self, "Nothing to Export", "Load or run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Markdown", str(Path.home() / "reconmap_report.md"), "Markdown Files (*.md)")
        if not path:
            return
        try:
            out = export_markdown(path, self.current_hosts, self.current_findings, self.current_steps)
            self.statusBar().showMessage(f"Exported report to {out}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export Error", str(exc))

    def clear_tables(self) -> None:
        for table in [self.hosts_table, self.services_table, self.findings_table, self.steps_table]:
            table.setRowCount(0)

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from reconmap.gui.main_window import MainWindow


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("ReconMap")
    window = MainWindow()
    window.show()

    if not window.scanner.nmap_path:
        QMessageBox.warning(
            window,
            "Nmap Not Found",
            "Nmap was not found in PATH. Install nmap before running scans.\n\n"
            "You can still open and parse existing XML files.",
        )

    sys.exit(app.exec())

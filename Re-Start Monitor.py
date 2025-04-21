import sys
import os
import time
import subprocess
import json
from cryptography.fernet import Fernet  # Biblioteca para cifrado
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QTimeEdit, QHeaderView, QSpinBox, QComboBox, QAction, QMenu, QProgressBar,
    QTextEdit, QTabWidget, QFileDialog
)
from PyQt5.QtCore import QTimer, QDateTime, QDate, QTime
from PyQt5.QtGui import QIcon, QColor
from plyer import notification  # Biblioteca para notificaciones
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Clave secreta para cifrar/descifrar (DEBE SER SEGURA Y ÚNICA)
try:
    with open("secret_key.key", "rb") as key_file:
        SECRET_KEY = key_file.read()
except FileNotFoundError:
    SECRET_KEY = Fernet.generate_key()
    with open("secret_key.key", "wb") as key_file:
        key_file.write(SECRET_KEY)
cipher_suite = Fernet(SECRET_KEY)

# Verificar si ya hay una instancia en ejecución
LOCK_FILE = "program_lock.lock"

def check_single_instance():
    if os.path.exists(LOCK_FILE):
        print("Ya hay una instancia en ejecución.")
        sys.exit(0)  # Salir si ya hay una instancia
    else:
        # Crear el archivo de bloqueo
        with open(LOCK_FILE, "w") as lock:
            lock.write(str(os.getpid()))

def remove_lock_file():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

class EditConfigurationDialog(QDialog):
    def __init__(self, configuration, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Editar Configuración")
        self.setFixedSize(400, 300)
        self.configuration = configuration
        layout = QVBoxLayout()
        # Hora
        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        self.time_edit.setTime(QTime.fromString(configuration["time"], "HH:mm"))
        layout.addWidget(QLabel("Hora:"))
        layout.addWidget(self.time_edit)
        # IPs
        self.ip_input = QLineEdit(", ".join(configuration["ips"]))
        layout.addWidget(QLabel("Direcciones IP (separadas por comas):"))
        layout.addWidget(self.ip_input)
        # Intentos
        self.attempts_input = QSpinBox()
        self.attempts_input.setMinimum(1)
        self.attempts_input.setValue(configuration["attempts"])
        layout.addWidget(QLabel("Intentos:"))
        layout.addWidget(self.attempts_input)
        # Intervalo
        self.interval_input = QSpinBox()
        self.interval_input.setMinimum(1)
        self.interval_input.setValue(configuration["interval"])
        layout.addWidget(QLabel("Intervalo (segundos):"))
        layout.addWidget(self.interval_input)
        # Día
        self.day_combo = QComboBox()
        self.day_combo.addItem("Todos los días")
        self.day_combo.addItems(["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"])
        self.day_combo.setCurrentText(configuration["day"])
        layout.addWidget(QLabel("Día:"))
        layout.addWidget(self.day_combo)
        # Botón Guardar
        self.save_button = QPushButton("Guardar Cambios")
        self.save_button.clicked.connect(self.accept)
        layout.addWidget(self.save_button)
        self.setLayout(layout)

    def get_configuration(self):
        """Devuelve la configuración editada."""
        ips = [ip.strip() for ip in self.ip_input.text().split(",") if ip.strip()]
        return {
            "time": self.time_edit.time().toString("HH:mm"),
            "ips": ips,
            "attempts": self.attempts_input.value(),
            "interval": self.interval_input.value(),
            "day": self.day_combo.currentText()
        }

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitoreo y Reinicio Automático")
        self.setGeometry(100, 100, 800, 600)

        # Establecer el ícono de la ventana
        icon_path = "Reiniciar.png"  # Asegúrate de que este archivo exista en el directorio
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            print(f"No se encontró el ícono en la ruta: {icon_path}")

        # Historial de eventos y gráficos
        self.event_log = []
        self.ping_history = {}

        # Compatibilidad multiplataforma
        self.is_windows = sys.platform == "win32"

        # Configuraciones y temporizador
        self.configurations = []
        self.load_configurations()  # Cargar configuraciones guardadas
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_ping)
        self.init_ui()

        # Iniciar monitoreo automáticamente si hay configuraciones
        if self.configurations:
            self.timer.start(60000)  # Check every minute
            self.start_button.setText("Monitoreando")

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # Tabs para organizar la interfaz
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # Pestaña de Configuraciones
        config_tab = QWidget()
        config_layout = QVBoxLayout()
        config_tab.setLayout(config_layout)
        tab_widget.addTab(config_tab, "Configuraciones")

        # Configuration Section
        config_form_layout = QHBoxLayout()
        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        self.time_edit.setToolTip("Selecciona la hora para el monitoreo.")
        config_form_layout.addWidget(QLabel("Hora:"))
        config_form_layout.addWidget(self.time_edit)
        self.ip_input = QLineEdit()
        self.ip_input.setToolTip("Ingresa las direcciones IP separadas por comas (por ejemplo, 192.168.1.1, 8.8.8.8).")
        config_form_layout.addWidget(QLabel("Direcciones IP:"))
        config_form_layout.addWidget(self.ip_input)
        self.attempts_input = QSpinBox()
        self.attempts_input.setMinimum(1)
        self.attempts_input.setToolTip("Número de intentos antes de reiniciar.")
        config_form_layout.addWidget(QLabel("Intentos:"))
        config_form_layout.addWidget(self.attempts_input)
        self.interval_input = QSpinBox()
        self.interval_input.setMinimum(1)
        self.interval_input.setToolTip("Intervalo entre intentos (en segundos).")
        config_form_layout.addWidget(QLabel("Intervalo (segundos):"))
        config_form_layout.addWidget(self.interval_input)
        self.day_combo = QComboBox()
        self.day_combo.addItem("Todos los días")
        self.day_combo.addItems(["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"])
        self.day_combo.setToolTip("Selecciona el día para el monitoreo.")
        config_form_layout.addWidget(QLabel("Día:"))
        config_form_layout.addWidget(self.day_combo)
        add_button = QPushButton("Agregar Configuración")
        add_button.setToolTip("Haz clic aquí para agregar una nueva configuración.")
        add_button.clicked.connect(self.add_configuration)
        config_form_layout.addWidget(add_button)
        config_layout.addLayout(config_form_layout)

        # Table to display configurations
        self.table = QTableWidget()
        self.table.setColumnCount(6)  # Nueva columna para indicadores visuales
        self.table.setHorizontalHeaderLabels(["Hora", "IPs", "Intentos", "Intervalo", "Día", "Estado"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        config_layout.addWidget(self.table)

        # Buttons for Delete and Edit
        buttons_layout = QHBoxLayout()
        delete_button = QPushButton("Eliminar Configuración")
        delete_button.setToolTip("Haz clic aquí para eliminar la configuración seleccionada.")
        delete_button.clicked.connect(self.delete_configuration)
        buttons_layout.addWidget(delete_button)
        edit_button = QPushButton("Editar Configuración")
        edit_button.setToolTip("Haz clic aquí para editar la configuración seleccionada.")
        edit_button.clicked.connect(self.edit_configuration)
        buttons_layout.addWidget(edit_button)
        config_layout.addLayout(buttons_layout)

        # Start Monitoring Button
        self.start_button = QPushButton("Iniciar Monitoreo")
        self.start_button.setToolTip("Haz clic aquí para iniciar/detener el monitoreo.")
        self.start_button.clicked.connect(self.toggle_monitoring)
        config_layout.addWidget(self.start_button)

        # Progress Bar for Countdown
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(60)  # 60 segundos
        self.progress_bar.setVisible(False)
        config_layout.addWidget(self.progress_bar)

        # Cancel Restart Button
        self.cancel_restart_button = QPushButton("Cancelar Reinicio")
        self.cancel_restart_button.setVisible(False)
        self.cancel_restart_button.clicked.connect(self.cancel_restart)
        config_layout.addWidget(self.cancel_restart_button)

        # Pestaña de Historial de Eventos
        history_tab = QWidget()
        history_layout = QVBoxLayout()
        history_tab.setLayout(history_layout)
        tab_widget.addTab(history_tab, "Historial de Eventos")
        self.event_log_text = QTextEdit()
        self.event_log_text.setReadOnly(True)
        history_layout.addWidget(self.event_log_text)

        # Pestaña de Gráfico de Monitoreo
        graph_tab = QWidget()
        graph_layout = QVBoxLayout()
        graph_tab.setLayout(graph_layout)
        tab_widget.addTab(graph_tab, "Gráfico de Monitoreo")
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        graph_layout.addWidget(self.canvas)

        # Menú contextual
        menu = self.menuBar()
        options_menu = menu.addMenu("Opciones")
        help_action = QAction("Ayuda", self)
        help_action.triggered.connect(self.show_help)
        options_menu.addAction(help_action)
        about_action = QAction("Acerca de", self)
        about_action.triggered.connect(self.show_about)
        options_menu.addAction(about_action)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Actualizar la tabla con las configuraciones cargadas
        self.update_table()

    def load_configurations(self):
        """Carga las configuraciones desde un archivo JSON cifrado."""
        try:
            with open("configurations.enc", "rb") as file:
                encrypted_data = file.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                self.configurations = json.loads(decrypted_data)
        except FileNotFoundError:
            self.configurations = []  # No hay configuraciones guardadas

    def save_configurations(self):
        """Guarda las configuraciones en un archivo JSON cifrado."""
        encrypted_data = cipher_suite.encrypt(json.dumps(self.configurations).encode())
        with open("configurations.enc", "wb") as file:
            file.write(encrypted_data)

    def add_configuration(self):
        time = self.time_edit.time().toString("HH:mm")
        ips = self.ip_input.text().strip().split(",")  # Lista de IPs separadas por comas
        ips = [ip.strip() for ip in ips if ip.strip()]  # Limpiar espacios y eliminar IPs vacías
        attempts = self.attempts_input.value()
        interval = self.interval_input.value()
        day = self.day_combo.currentText()

        # Validación de entrada
        if not ips or not all(self.validate_ip(ip) for ip in ips):
            QMessageBox.warning(self, "Error", "Por favor, ingrese direcciones IP válidas.")
            return

        self.configurations.append({
            "time": time,
            "ips": ips,  # Guardar como lista de IPs
            "attempts": attempts,
            "interval": interval,
            "day": day
        })
        self.save_configurations()  # Guardar configuraciones cifradas
        self.update_table()

    def validate_ip(self, ip):
        """Valida una dirección IP."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True

    def update_table(self):
        self.table.setRowCount(len(self.configurations))
        for row, config in enumerate(self.configurations):
            self.table.setItem(row, 0, QTableWidgetItem(config["time"]))
            self.table.setItem(row, 1, QTableWidgetItem(", ".join(config["ips"])))  # Mostrar IPs como texto
            self.table.setItem(row, 2, QTableWidgetItem(str(config["attempts"])))
            self.table.setItem(row, 3, QTableWidgetItem(str(config["interval"])))
            self.table.setItem(row, 4, QTableWidgetItem(config["day"]))
            status_item = QTableWidgetItem("✅" if config.get("status", "success") else "❌")
            status_item.setForeground(QColor("green") if config.get("status", "success") else QColor("red"))
            self.table.setItem(row, 5, status_item)

    def delete_configuration(self):
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Error", "Selecciona una configuración para eliminar.")
            return

        # Eliminar la configuración seleccionada
        del self.configurations[selected_row]
        self.save_configurations()  # Guardar configuraciones cifradas
        self.update_table()

    def edit_configuration(self):
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Error", "Selecciona una configuración para editar.")
            return

        # Obtener la configuración seleccionada
        configuration = self.configurations[selected_row]

        # Abrir el diálogo de edición
        dialog = EditConfigurationDialog(configuration, self)
        if dialog.exec_() == QDialog.Accepted:
            # Obtener la configuración editada
            edited_config = dialog.get_configuration()

            # Validar IPs
            if not all(self.validate_ip(ip) for ip in edited_config["ips"]):
                QMessageBox.warning(self, "Error", "Por favor, ingrese direcciones IP válidas.")
                return

            # Actualizar la configuración
            self.configurations[selected_row] = edited_config
            self.save_configurations()  # Guardar configuraciones cifradas
            self.update_table()

    def toggle_monitoring(self):
        if not self.timer.isActive():
            self.timer.start(60000)  # Check every minute
            self.start_button.setText("Monitoreando")
        else:
            self.timer.stop()
            self.start_button.setText("Iniciar Monitoreo")

    def check_ping(self):
        current_time = QDateTime.currentDateTime().toString("HH:mm")
        current_day = QDate.currentDate().toString("dddd")  # Día actual en texto (e.g., "Lunes")
        for config in self.configurations:
            if config["time"] == current_time:
                # Verificar si el día coincide o si es "Todos los días"
                if config["day"] == "Todos los días" or config["day"] == current_day:
                    ips = config["ips"]
                    attempts = config["attempts"]
                    interval = config["interval"]
                    success = False
                    for _ in range(attempts):
                        # Verificar todas las IPs
                        if any(self.ping_ip(ip) for ip in ips):
                            success = True
                            break
                        time.sleep(interval)
                    config["status"] = success
                    self.update_table()
                    self.log_event(f"{'Éxito' if success else 'Fallo'} en {', '.join(ips)}")
                    if not success:
                        self.show_restart_warning()
                    self.update_graph(config, success)

    def ping_ip(self, ip):
        """Verifica si una IP responde al ping."""
        try:
            command = ["ping", "-n" if self.is_windows else "-c", "1", ip]
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if "TTL=" in result.stdout:  # TTL indica que la IP respondió correctamente
                return True
            else:
                return False
        except Exception as e:
            print(f"Error al hacer ping a {ip}: {str(e)}")
            return False

    def show_restart_warning(self):
        """Muestra una advertencia y cuenta regresiva antes de reiniciar la PC."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(60)  # Inicia en 60 segundos
        self.cancel_restart_button.setVisible(True)

        # Notificación al usuario
        notification.notify(
            title="Advertencia",
            message="La PC se reiniciará en 60 segundos debido a fallo de conectividad.",
            app_name="Monitoreo y Reinicio Automático",
            timeout=10
        )

        # Crear un temporizador persistente
        self.restart_timer = QTimer()
        self.restart_timer.setInterval(1000)  # Intervalo de 1 segundo
        countdown = 60  # Contador inicial

        def update_countdown():
            """Actualiza la barra de progreso y verifica si ha llegado a cero."""
            nonlocal countdown
            countdown -= 1
            if countdown >= 0:
                self.progress_bar.setValue(countdown)  # Actualiza la barra de progreso
            else:
                # Detener el temporizador y reiniciar la PC
                self.restart_timer.stop()
                self.progress_bar.setVisible(False)
                self.cancel_restart_button.setVisible(False)
                self.restart_pc()  # Reiniciar la PC automáticamente

        # Conectar el temporizador a la función de actualización
        self.restart_timer.timeout.connect(update_countdown)
        self.restart_timer.start()  # Iniciar el temporizador

    def cancel_restart(self):
        """Cancela el reinicio programado."""
        if hasattr(self, "restart_timer") and self.restart_timer.isActive():
            self.restart_timer.stop()
        self.progress_bar.setVisible(False)
        self.cancel_restart_button.setVisible(False)

    def restart_pc(self):
        """Reinicia la PC."""
        try:
            command = "shutdown /r /t 0" if self.is_windows else "sudo reboot"
            subprocess.run(command, shell=True, check=True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo reiniciar la PC: {str(e)}")

    def log_event(self, message):
        """Registra un evento en el archivo de log."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        log_entry = f"{timestamp} - {message}"
        self.event_log.append(log_entry)
        self.event_log_text.append(log_entry)

    def update_graph(self, config, success):
        """Actualiza el gráfico de monitoreo."""
        ip_key = ", ".join(config["ips"])
        if ip_key not in self.ping_history:
            self.ping_history[ip_key] = {"times": [], "results": []}
        self.ping_history[ip_key]["times"].append(QDateTime.currentDateTime().toString("HH:mm"))
        self.ping_history[ip_key]["results"].append(1 if success else 0)
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        for ip, data in self.ping_history.items():
            ax.plot(data["times"], data["results"], label=ip, marker="o")
        ax.set_ylim(-0.5, 1.5)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(["Fallo", "Éxito"])
        ax.legend()
        self.canvas.draw()

    def show_help(self):
        """Muestra el manual de usuario."""
        QMessageBox.information(self, "Ayuda", "Este es el manual de usuario.\n"
                                              "1. Agrega configuraciones usando la pestaña 'Configuraciones'.\n"
                                              "2. Monitorea las IPs y visualiza el historial en 'Historial de Eventos'.\n"
                                              "3. Usa el gráfico en 'Gráfico de Monitoreo' para ver tendencias.")

    def show_about(self):
        """Muestra la información del desarrollador."""
        QMessageBox.about(self, "Acerca de", "Desarrollado por Alejandro Peña Basulto\n"
                                            "Versión 1.0\n"
                                            "Contacto: penabasulto@gmail.com")


if __name__ == "__main__":
    # Verificar si ya hay una instancia en ejecución
    check_single_instance()

    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()

    # Al cerrar la aplicación, eliminar el archivo de bloqueo
    app.aboutToQuit.connect(remove_lock_file)

    sys.exit(app.exec_())

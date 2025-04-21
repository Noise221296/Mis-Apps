from PyQt5.QtWidgets import (
    QApplication, QLabel, QVBoxLayout, QWidget, QPushButton, QFileDialog,
    QMessageBox, QDialog, QLineEdit, QFormLayout, QAction, QMenuBar, QInputDialog, QSystemTrayIcon, QMenu
)
from PyQt5.QtCore import QTimer, Qt, QSettings
from PyQt5.QtGui import QIcon
import sys
import json
import os
from datetime import datetime
import requests
import base64  # Para codificar las credenciales en Base64

# Contraseña de administrador (puedes cambiarla según sea necesario)
ADMIN_PASSWORD = "Noise1996*"

class CredentialDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Credenciales del Proxy")
        self.setGeometry(200, 200, 300, 150)

        # Layout principal
        layout = QFormLayout()

        # Campo para el nombre de usuario
        self.username_input = QLineEdit(self)
        layout.addRow("Usuario:", self.username_input)

        # Campo para la contraseña
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Contraseña:", self.password_input)

        # Botón para aceptar
        self.accept_button = QPushButton("Aceptar", self)
        self.accept_button.clicked.connect(self.accept)
        layout.addWidget(self.accept_button)

        self.setLayout(layout)

    def get_credentials(self):
        return self.username_input.text(), self.password_input.text()


class AdminPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Acceso de Administrador")
        self.setGeometry(200, 200, 300, 150)

        # Layout principal
        layout = QFormLayout()

        # Campo para la contraseña de administrador
        self.admin_password_input = QLineEdit(self)
        self.admin_password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Contraseña de Admin:", self.admin_password_input)

        # Botón para aceptar
        self.accept_button = QPushButton("Aceptar", self)
        self.accept_button.clicked.connect(self.accept)
        layout.addWidget(self.accept_button)

        self.setLayout(layout)

    def get_password(self):
        return self.admin_password_input.text()


class InternetStatusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.proxy_url = "http://192.168.124.202:3128"  # URL del proxy
        self.proxy_auth = self.get_proxy_credentials()  # Solicitar credenciales al iniciar
        if not self.proxy_auth:
            QMessageBox.critical(self, "Error", "No se proporcionaron credenciales válidas. La aplicación se cerrará.")
            sys.exit()
        
        self.initUI()
        self.history = []  # Para almacenar el historial de desconexiones
        self.check_interval = 2000  # Intervalo predeterminado en milisegundos (2 segundos)
        self.is_connected = None  # Estado inicial desconocido
        self.disconnect_time = None  # Marca de tiempo cuando se pierde la conexión
        self.check_connection()

        # Configuración para iniciar con el sistema
        self.setup_autostart()

        # Configuración del ícono en la bandeja del sistema
        self.setup_tray_icon()

    def setup_autostart(self):
        """Configura la aplicación para iniciar automáticamente con el sistema."""
        if sys.platform == "win32":
            # Ruta del registro de Windows para programas de inicio
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "InternetStatusApp"
            app_path = os.path.abspath(sys.argv[0])  # Ruta del ejecutable actual

            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, app_path)
            except Exception as e:
                QMessageBox.warning(self, "Advertencia", f"No se pudo configurar el inicio automático: {str(e)}")

    def setup_tray_icon(self):
        """Configura el ícono en la bandeja del sistema."""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("wifi_icon.png"))  # Ícono para la bandeja del sistema

        # Menú contextual para el ícono de la bandeja
        tray_menu = QMenu()
        restore_action = tray_menu.addAction("Restaurar")
        restore_action.triggered.connect(self.showNormal)  # Restaurar la ventana principal
        quit_action = tray_menu.addAction("Salir")
        quit_action.triggered.connect(QApplication.quit)  # Salir de la aplicación

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)  # Manejar clics en el ícono
        self.tray_icon.show()

    def on_tray_icon_activated(self, reason):
        """Maneja los eventos de clic en el ícono de la bandeja."""
        if reason == QSystemTrayIcon.DoubleClick:
            self.showNormal()  # Restaurar la ventana principal si se hace doble clic

    def closeEvent(self, event):
        """Sobrescribe el evento de cierre para minimizar a la bandeja en lugar de cerrar."""
        event.ignore()  # Ignorar el evento de cierre
        self.hide()  # Ocultar la ventana principal
        self.tray_icon.showMessage(
            "Aplicación Minimizada",
            "La aplicación se ha minimizado a la bandeja del sistema.",
            QSystemTrayIcon.Information,
            2000  # Duración del mensaje en milisegundos
        )

    def initUI(self):
        self.setWindowTitle("Detector de Conexión a Internet")
        self.setGeometry(100, 100, 400, 300)
        self.setWindowIcon(QIcon("wifi_icon.png"))  # Agrega un ícono a la ventana

        # Crear un layout vertical principal
        main_layout = QVBoxLayout()

        # Crear un menú
        menubar = QMenuBar(self)  # El menú debe estar vinculado a la ventana principal
        options_menu = menubar.addMenu("Opciones")

        # Acción para modificar el proxy (protegida por contraseña de admin)
        modify_proxy_action = QAction("Modificar Proxy", self)
        modify_proxy_action.triggered.connect(self.modify_proxy_settings)
        options_menu.addAction(modify_proxy_action)

        # Acción para exportar el historial
        export_history_action = QAction("Exportar Historial", self)
        export_history_action.triggered.connect(self.export_history)
        options_menu.addAction(export_history_action)

        # Añadir el menú al layout principal
        main_layout.setMenuBar(menubar)

        # Etiqueta para mostrar el estado
        self.status_label = QLabel("Comprobando estado de conexión...", self)
        self.status_label.setStyleSheet("font-size: 18px; color: white; padding: 10px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

    def check_connection(self):
        # Usar un QTimer para comprobar la conexión cada X segundos
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(self.check_interval)  # Intervalo configurable

    def update_status(self):
        try:
            # Codificar las credenciales en Base64 para autenticación básica
            username, password = self.proxy_auth
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

            headers = {
                "Proxy-Authorization": f"Basic {encoded_credentials}"
            }

            # Intentar realizar una solicitud HTTP a través del proxy
            response = requests.get(
                "http://www.google.com",  # URL de prueba
                proxies={"http": self.proxy_url, "https": self.proxy_url},
                headers=headers,
                timeout=5  # Tiempo de espera máximo en segundos
            )
            if response.status_code == 200:
                if self.is_connected is False:  # Si estaba desconectado previamente
                    self.is_connected = True
                    self.show_notification("Conexión Restablecida")
                    self.log_reconnection()
                self.status_label.setText("Conectado a Internet")
                self.status_label.setStyleSheet("background-color: green; font-size: 18px; color: white; padding: 10px;")
            else:
                raise ConnectionError(f"Respuesta no válida del servidor: {response.status_code}")
        except requests.exceptions.Timeout:
            if self.is_connected is True or self.is_connected is None:
                self.is_connected = False
                self.disconnect_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.show_notification("Sin Conexión a Internet (Timeout)")
            self.status_label.setText("Sin conexión a Internet (Timeout)")
            self.status_label.setStyleSheet("background-color: red; font-size: 18px; color: white; padding: 10px;")
        except requests.exceptions.ConnectionError:
            if self.is_connected is True or self.is_connected is None:
                self.is_connected = False
                self.disconnect_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.show_notification("Sin Conexión a Internet (Error de Conexión)")
            self.status_label.setText("Sin conexión a Internet (Error de Conexión)")
            self.status_label.setStyleSheet("background-color: red; font-size: 18px; color: white; padding: 10px;")
        except Exception as e:
            if self.is_connected is True or self.is_connected is None:
                self.is_connected = False
                self.disconnect_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.show_notification(f"Sin Conexión a Internet ({str(e)})")
            self.status_label.setText("Sin conexión a Internet")
            self.status_label.setStyleSheet("background-color: red; font-size: 18px; color: white; padding: 10px;")

    def log_reconnection(self):
        # Registrar el tiempo desde que se perdió la conexión hasta que se restableció
        reconnection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history.append({
            "disconnect_time": self.disconnect_time,
            "reconnect_time": reconnection_time
        })
        print(f"Desconexión registrada: {self.disconnect_time} - Reconexión: {reconnection_time}")
        self.disconnect_time = None  # Reiniciar el tiempo de desconexión

    def show_notification(self, message):
        # Mostrar una notificación emergente
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(message)
        msg_box.setWindowTitle("Estado de Conexión")
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    def export_history(self):
        # Exportar el historial a un archivo JSON
        if not self.history:
            QMessageBox.warning(self, "Historial Vacío", "No hay historial para exportar.")
            return

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Guardar Historial", "", "Archivos JSON (*.json)", options=options)
        if file_path:
            with open(file_path, "w") as file:
                json.dump(self.history, file, indent=4)
            QMessageBox.information(self, "Éxito", "Historial exportado correctamente.")

    def modify_proxy_settings(self):
        # Solicitar la contraseña de administrador
        dialog = AdminPasswordDialog()
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.get_password()
            if password == ADMIN_PASSWORD:
                # Permitir modificar la configuración del proxy
                new_proxy_url, ok = QInputDialog.getText(self, "Modificar Proxy", "Ingrese la nueva URL del proxy:")
                if ok and new_proxy_url.strip():
                    self.proxy_url = new_proxy_url.strip()
                    QMessageBox.information(self, "Éxito", "La configuración del proxy ha sido actualizada.")
                else:
                    QMessageBox.warning(self, "Advertencia", "No se ingresó una URL válida.")
            else:
                QMessageBox.warning(self, "Acceso Denegado", "Contraseña de administrador incorrecta.")

    def get_proxy_credentials(self):
        while True:
            dialog = CredentialDialog()
            if dialog.exec_() == QDialog.Accepted:
                username, password = dialog.get_credentials()
                if username.strip() and password.strip():  # Validar que no estén vacíos
                    try:
                        # Codificar las credenciales en Base64 para autenticación básica
                        credentials = f"{username}:{password}"
                        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

                        headers = {
                            "Proxy-Authorization": f"Basic {encoded_credentials}"
                        }
                        response = requests.get(
                            "http://www.google.com",  # URL de prueba
                            proxies={"http": self.proxy_url, "https": self.proxy_url},
                            headers=headers,
                            timeout=5  # Tiempo de espera máximo en segundos
                        )
                        if response.status_code == 200:
                            return (username, password)  # Credenciales válidas
                        elif response.status_code == 407:
                            QMessageBox.warning(self, "Error", "Credenciales inválidas. Intente nuevamente.")
                        else:
                            QMessageBox.warning(self, "Error", f"Respuesta inesperada del proxy: {response.status_code}")
                    except requests.exceptions.Timeout:
                        QMessageBox.warning(self, "Error", "Tiempo de espera agotado. Verifique su conexión.")
                    except requests.exceptions.ConnectionError:
                        QMessageBox.warning(self, "Error", "No se pudo conectar al proxy. Verifique su configuración.")
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Error inesperado: {str(e)}")
                else:
                    QMessageBox.warning(self, "Advertencia", "Debe proporcionar un usuario y una contraseña válidos.")
            else:
                sys.exit()  # Salir si el usuario cancela el diálogo


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # Evitar que la aplicación se cierre al cerrar la ventana principal
    window = InternetStatusApp()
    window.show()
    sys.exit(app.exec_())
import asyncio
import json
import os
import sys
import time

import ida_kernwin
import idaapi
from PyQt5 import QtCore, QtWidgets

from ainalyse import DEFAULT_CONFIG, get_config_validation_issues, save_config, sanitize_config, test_mcp_connection
from ainalyse.function_selection import FunctionSelectionDialog
from ainalyse.ssl_helper import create_openai_client_with_custom_ca

from ainalyse.async_manager import schedule_ui_task

# --- Analysis History Dialog ---
class AnalysisHistoryDialog(QtWidgets.QDialog):
    def __init__(self, history, parent=None):
        super(AnalysisHistoryDialog, self).__init__()
        self.setWindowTitle("AI Analysis History")
        self.setMinimumSize(600, 400)
        self.history = history
        
        layout = QtWidgets.QVBoxLayout()
        
        # Header
        header_label = QtWidgets.QLabel("Analysis History (most recent first):")
        header_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # List widget
        self.list_widget = QtWidgets.QListWidget()
        for i, entry in enumerate(reversed(history)):
            try:
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("timestamp", 0)))
                func_name = entry.get("starting_function", "unknown")
                item_text = f"Analysis from {func_name}()\n{timestamp_str}"
                
                list_item = QtWidgets.QListWidgetItem(item_text)
                list_item.setData(QtCore.Qt.UserRole, len(history) - 1 - i)  # Store original index
                self.list_widget.addItem(list_item)
            except Exception as e:
                print(f"[AETHER] Error processing history entry: {e}")
        
        layout.addWidget(self.list_widget)
        
        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.open_button = QtWidgets.QPushButton("Open")
        self.open_button.clicked.connect(self.open_analysis)
        button_layout.addWidget(self.open_button)
        
        button_layout.addStretch()
        
        self.close_button = QtWidgets.QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Enable open button only when item is selected
        self.list_widget.itemSelectionChanged.connect(self.update_buttons)
        self.update_buttons()
    
    def update_buttons(self):
        has_selection = bool(self.list_widget.currentItem())
        self.open_button.setEnabled(has_selection)
    
    def open_analysis(self):
        current_item = self.list_widget.currentItem()
        if not current_item:
            return
            
        entry_index = current_item.data(QtCore.Qt.UserRole)
        entry = self.history[entry_index]
        
        # Show detailed dialog
        detail_dlg = AnalysisDetailDialog(entry, entry_index == len(self.history) - 1)
        detail_dlg.exec_()

class AnalysisDetailDialog(QtWidgets.QDialog):
    def __init__(self, entry, is_latest=False, parent=None):
        super(AnalysisDetailDialog, self).__init__()
        self.entry = entry
        self.is_latest = is_latest
        
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("timestamp", 0)))
        func_name = entry.get("starting_function", "unknown")
        self.setWindowTitle(f"Analysis Details - {func_name}() - {timestamp_str}")
        self.setMinimumSize(800, 600)
        
        layout = QtWidgets.QVBoxLayout()
        
        # Info section - use simple labels instead of QFormLayout
        info_text = f"Function: {func_name}\nTimestamp: {timestamp_str}\n"
        gatherer_prompt = entry.get("gatherer_prompt", "")
        annotator_prompt = entry.get("annotator_prompt", "")
        if gatherer_prompt:
            info_text += f"Gatherer Context: {gatherer_prompt[:100]}{'...' if len(gatherer_prompt) > 100 else ''}\n"
        if annotator_prompt:
            info_text += f"Annotator Context: {annotator_prompt[:100]}{'...' if len(annotator_prompt) > 100 else ''}\n"
        
        info_label = QtWidgets.QLabel(info_text)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Tabs for outputs
        tab_widget = QtWidgets.QTabWidget()
        
        # Gatherer output tab
        gatherer_tab = QtWidgets.QWidget()
        gatherer_layout = QtWidgets.QVBoxLayout()
        gatherer_text = QtWidgets.QTextEdit()
        gatherer_text.setPlainText(entry.get("gatherer_output", "No gatherer output available."))
        gatherer_text.setReadOnly(True)
        gatherer_layout.addWidget(gatherer_text)
        gatherer_tab.setLayout(gatherer_layout)
        tab_widget.addTab(gatherer_tab, "Gatherer Output")
        
        # Annotator output tab
        annotator_tab = QtWidgets.QWidget()
        annotator_layout = QtWidgets.QVBoxLayout()
        annotator_text = QtWidgets.QTextEdit()
        annotator_text.setPlainText(entry.get("annotator_output", "No annotator output available."))
        annotator_text.setReadOnly(True)
        annotator_layout.addWidget(annotator_text)
        annotator_tab.setLayout(annotator_layout)
        tab_widget.addTab(annotator_tab, "Annotator Output")
        
        layout.addWidget(tab_widget)
        
        # Buttons - always show undo/retry buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.undo_button = QtWidgets.QPushButton("Undo Annotations (best-effort)")
        self.undo_button.clicked.connect(self.undo_annotations)
        button_layout.addWidget(self.undo_button)
        
        self.retry_button = QtWidgets.QPushButton("Retry")
        self.retry_button.clicked.connect(self.retry_analysis)
        button_layout.addWidget(self.retry_button)
        
        button_layout.addStretch()
        
        self.close_button = QtWidgets.QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def undo_annotations(self):
        self.close()
        # Import here to avoid circular imports
        from plugin import UndoAnnotationHandler
        # Trigger undo handler
        handler = UndoAnnotationHandler()
        handler.activate(None)
    
    def retry_analysis(self):
        self.close()
        # Import here to avoid circular imports
        from plugin import RetryAnnotationHandler
        # Trigger retry handler
        handler = RetryAnnotationHandler()
        handler.activate(None)

# --- Advanced Options Dialog ---
class AdvancedOptionsDialog(QtWidgets.QDialog):
    def __init__(self, current_function_name, base_config, gatherer_prompt="", annotator_prompt="", parent=None):
        super(AdvancedOptionsDialog, self).__init__()
        self.setWindowTitle("AETHER (advanced options)")
        self.base_config = base_config.copy()
        self.current_function_name = current_function_name

        # --- Function Label ---
        function_label = QtWidgets.QLabel(f"Start analysis from function '{current_function_name}' with these options:")
        function_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")

        # --- Analysis Mode Section ---
        mode_section = QtWidgets.QGroupBox("Analysis Mode")
        mode_layout = QtWidgets.QVBoxLayout()
        
        mode_layout.addWidget(QtWidgets.QLabel("<b>Active Model:</b>"))
        self.combo = QtWidgets.QComboBox()
        
        model_map = self.base_config.get("MODEL_LIST", {})
        current_id = self.base_config.get("OPENAI_MODEL", "")

        current_display_name = next(
            (name for name, mid in model_map.items() if mid == current_id), 
            current_id
        )
        for name, mid in sorted(model_map.items()):
            self.combo.addItem(name, mid)

        existing_index = self.combo.findData(current_id)
        if existing_index == -1:
            self.combo.insertItem(0, current_display_name, current_id)
            self.combo.setCurrentIndex(0)
        else:
            self.combo.setCurrentIndex(existing_index)
        
        mode_layout.addWidget(self.combo)

        self.auto_mode_radio = QtWidgets.QRadioButton("Automatic (LLM-guided gatherer)")
        self.auto_mode_radio.setChecked(True)
        mode_layout.addWidget(self.auto_mode_radio)
        
        self.manual_mode_radio = QtWidgets.QRadioButton("Manual (select functions manually)")
        mode_layout.addWidget(self.manual_mode_radio)
        
        self.manual_gatherer_button = QtWidgets.QPushButton("Select Functions Manually...")
        self.manual_gatherer_button.setEnabled(False)
        self.manual_gatherer_button.clicked.connect(self.open_manual_gatherer)
        mode_layout.addWidget(self.manual_gatherer_button)
        
        self.manual_mode_radio.toggled.connect(self.manual_gatherer_button.setEnabled)
        
        mode_section.setLayout(mode_layout)

        # --- Gatherer Context Section ---
        gatherer_section = QtWidgets.QGroupBox("Additional Context for Gatherer")
        gatherer_layout = QtWidgets.QVBoxLayout()
        gatherer_layout.addWidget(QtWidgets.QLabel(
            "You can provide additional context which you think might be useful."
        ))
        self.gatherer_textarea = QtWidgets.QTextEdit()
        self.gatherer_textarea.setPlainText(gatherer_prompt)
        self.gatherer_textarea.setPlaceholderText(
            "e.g. Focus on the decryption flows"
        )
        gatherer_layout.addWidget(self.gatherer_textarea)
        gatherer_layout.addWidget(QtWidgets.QLabel(
            "Warning: Additional context may disrupt the gatherer's operation."
        ))
        gatherer_section.setLayout(gatherer_layout)

        # --- Annotator Context Section ---
        annotator_section = QtWidgets.QGroupBox("Additional Context for Annotator")
        annotator_layout = QtWidgets.QVBoxLayout()
        annotator_layout.addWidget(QtWidgets.QLabel(
            "You can provide additional context which you think might be useful."
        ))
        self.annotator_textarea = QtWidgets.QTextEdit()
        self.annotator_textarea.setPlainText(annotator_prompt)
        self.annotator_textarea.setPlaceholderText(
            "e.g. This is a rootkit found on an embedded system"
        )
        annotator_layout.addWidget(self.annotator_textarea)
        annotator_layout.addWidget(QtWidgets.QLabel(
            "Warning: Additional context may disrupt the analyser's operation."
        ))
        annotator_section.setLayout(annotator_layout)

        # --- Filtering Options ---
        filter_section = QtWidgets.QGroupBox("Annotation Filtering")
        filter_layout = QtWidgets.QVBoxLayout()
        self.rename_filter_checkbox = QtWidgets.QCheckBox(
            "Only rename default-named functions (e.g., sub_XXXX) and variables (e.g., v1, a1)"
        )
        self.rename_filter_checkbox.setChecked(True)
        filter_layout.addWidget(self.rename_filter_checkbox)
        
        self.fast_mode_checkbox = QtWidgets.QCheckBox(
            "Use fast mode (simpler output format for faster processing)"
        )
        self.fast_mode_checkbox.setChecked(True)  # Set as default
        filter_layout.addWidget(self.fast_mode_checkbox)

        self.option_map = {
            "USE_DESC": "Enable Function Description",
            "USE_COMMENTS": "Enable Line Comments",
            "RENAME_VARS": "Enable Rename Variables",
            "RENAME_FUNCS": "Enable Rename Functions",
            "COMMENT_EVERY_LINE": "Comment on every line"
        }
        self.extra_option_check_boxes = {}

        for key, label in self.option_map.items():
            cb = QtWidgets.QCheckBox(label)
            # Load default from config, fallback to True if not present
            cb.setChecked(self.base_config.get(key, True))
            filter_layout.addWidget(cb)
            self.extra_option_check_boxes[key] = cb
        
        filter_section.setLayout(filter_layout)

        # --- Buttons ---
        self.ok_button = QtWidgets.QPushButton("Analyse")
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        # --- Main Layout ---
        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(function_label)
        main_layout.addWidget(mode_section)
        main_layout.addWidget(gatherer_section)
        main_layout.addWidget(annotator_section)
        main_layout.addWidget(filter_section)
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        # Store selected manual functions
        self.selected_manual_functions = []
    
    def open_manual_gatherer(self):
        """Open manual gatherer dialog."""
        try:
            # Get current function address
            ea = ida_kernwin.get_screen_ea()
            func = idaapi.get_func(ea)
            if func:
                current_func_addr = hex(func.start_ea)
                dlg = FunctionSelectionDialog(self.current_function_name, current_func_addr, "Manual Gatherer - Select Functions")
                if dlg.exec_():
                    self.selected_manual_functions = dlg.get_selected_functions()
                    self.manual_gatherer_button.setText(f"Selected {len(self.selected_manual_functions)} functions")
        except Exception as e:
            print(f"[AETHER] Error opening manual gatherer: {e}")

    def get_results(self):
        
        results = {
            "gatherer_context": self.gatherer_textarea.toPlainText(),
            "annotator_context": self.annotator_textarea.toPlainText(),
            "rename_filter_enabled": self.rename_filter_checkbox.isChecked(),
            "fast_mode": self.fast_mode_checkbox.isChecked(),
            "manual_mode": self.manual_mode_radio.isChecked(),
            "manual_functions": self.selected_manual_functions if self.manual_mode_radio.isChecked() else [],
            "OPENAI_MODEL": self.combo.currentData()
        }

        for key, cb in self.extra_option_check_boxes.items():
            results[key] = cb.isChecked()
        
        return results

# --- Plugin Settings Dialog ---
class PluginSettingsDialog(QtWidgets.QDialog):
    def __init__(self, config, parent=None):
        super(PluginSettingsDialog, self).__init__()
        self.setWindowTitle("AETHER Plugin Settings")
        self.setMinimumSize(700, 600)
        
        # Ensure all default config values are present for backwards compatibility
        self.config = config.copy()
        for key, default_value in DEFAULT_CONFIG.items():
            if key not in self.config:
                self.config[key] = default_value

        layout = QtWidgets.QVBoxLayout()

        # Header
        header_label = QtWidgets.QLabel("Global AETHER Plugin Settings")
        header_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(header_label)

        info_label = QtWidgets.QLabel("For best results - Deepseek R1-0528-level models if available; Qwen3 32b / Gemma 3 27b in a pinch for gatherer; Gemini 2.5 Flash for internet\n\nThese settings affect all future analyses:")
        info_label.setStyleSheet("margin-bottom: 10px;")
        layout.addWidget(info_label)

        # Config editor
        config_section = QtWidgets.QGroupBox("Configuration")
        config_layout = QtWidgets.QVBoxLayout()
        
        self.config_textarea = QtWidgets.QTextEdit()
        self.config_textarea.setPlainText(json.dumps(self.config, indent=2))
        self.config_textarea.setMaximumHeight(300)  # Set maximum height to prevent expansion
        self.config_textarea.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        config_layout.addWidget(self.config_textarea)
        
        config_section.setLayout(config_layout)
        layout.addWidget(config_section)

        # Test section
        test_section = QtWidgets.QGroupBox("Test Configuration")
        test_layout = QtWidgets.QVBoxLayout()
        
        self.test_button = QtWidgets.QPushButton("Test Configuration")
        self.test_button.clicked.connect(self.test_configuration)
        test_layout.addWidget(self.test_button)
        
        self.test_output = QtWidgets.QTextEdit()
        self.test_output.setReadOnly(True)
        self.test_output.setMaximumHeight(200)
        test_layout.addWidget(self.test_output)
        
        test_section.setLayout(test_layout)
        layout.addWidget(test_section)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.save_button = QtWidgets.QPushButton("Save Settings")
        self.save_button.clicked.connect(self.accept)
        button_layout.addWidget(self.save_button)
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def accept(self):
        """Only block invalid JSON; key/item correction is handled by save_config."""
        try:
            json.loads(self.config_textarea.toPlainText())
        except json.JSONDecodeError as e:
            ida_kernwin.warning(f"Cannot save settings: invalid JSON.\n\n{e}")
            return
        super().accept()

    def test_configuration(self):
        self.test_output.clear()
        self.test_output.setPlainText("Testing configuration...\n")
        self.test_button.setEnabled(False)
        
        try:
            config = json.loads(self.config_textarea.toPlainText())
        except json.JSONDecodeError as e:
            self.test_output.setPlainText(f"❌ Configuration is not valid.\nInvalid JSON: {e}")
            self.test_button.setEnabled(True)
            return

        async def run_tests():
            test_results = []
            config_ok = True
            try:
                issues = get_config_validation_issues(config)
                if issues:
                    config_ok = False
                    test_results.append("❌ Configuration schema validation failed:")
                    for issue in issues:
                        test_results.append(f"- {issue}")
                    return

                test_results.append("✅ Configuration schema validation passed")

                test_config, _ = sanitize_config(config)

                # Test 1: OpenAI API
                test_results.append("Testing configuration...\n")
                test_results.append("1. Testing OpenAI API connection...")
                
                if not test_config.get("OPENAI_API_KEY"):
                    config_ok = False
                    test_results.append("❌ OPENAI_API_KEY is not set")
                    return
                
                # Test custom CA certificate if provided
                custom_ca_cert_path = test_config.get("CUSTOM_CA_CERT_PATH", "")
                if custom_ca_cert_path:
                    if not os.path.exists(custom_ca_cert_path):
                        config_ok = False
                        test_results.append(f"❌ Custom CA certificate file not found at: {custom_ca_cert_path}")
                        return
                    else:
                        test_results.append(f"✅ Custom CA certificate found at: {custom_ca_cert_path}")
                
                # Test client certificate files if provided
                client_cert_path = test_config.get("CLIENT_CERT_PATH", "")
                client_key_path = test_config.get("CLIENT_KEY_PATH", "")
                if client_cert_path or client_key_path:
                    if client_cert_path and client_key_path:
                        if not os.path.exists(client_cert_path):
                            config_ok = False
                            test_results.append(f"❌ Client certificate file not found at: {client_cert_path}")
                            return
                        if not os.path.exists(client_key_path):
                            config_ok = False
                            test_results.append(f"❌ Client key file not found at: {client_key_path}")
                            return
                        test_results.append(f"✅ Client certificate found at: {client_cert_path}")
                        test_results.append(f"✅ Client key found at: {client_key_path}")
                    else:
                        config_ok = False
                        test_results.append("❌ Both CLIENT_CERT_PATH and CLIENT_KEY_PATH must be provided for mTLS")
                        return

                feature = "verify"        
                client = create_openai_client_with_custom_ca(
                    test_config["OPENAI_API_KEY"], 
                    test_config["OPENAI_BASE_URL"],
                    custom_ca_cert_path,
                    client_cert_path,
                    client_key_path,
                    feature
                )
                
                models = client.models.list()
                model_ids = [model.id for model in models.data]
                test_results.append(f"✅ API connection successful. Found {len(model_ids)} models")
                
                # Check if specified model exists
                if test_config["OPENAI_MODEL"] in model_ids:
                    test_results.append(f"✅ Model '{test_config['OPENAI_MODEL']}' is available")
                else:
                    config_ok = False
                    test_results.append(f"❌ Model '{test_config['OPENAI_MODEL']}' not found")
                    test_results.append(f"Available models: {', '.join(model_ids[:5])}...")
                
                # Test 2: MCP Server connection
                test_results.append("\n2. Testing MCP server connection...")
                
                if sys.platform == "win32":
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                
                success, message = await test_mcp_connection(test_config["MCP_SERVER_URL"])
                if success:
                    test_results.append(f"✅ {message}")
                else:
                    config_ok = False
                    test_results.append(f"❌ {message}")
                
            except Exception as e:
                config_ok = False
                test_results.append(f"❌ Test failed with error: {str(e)}")
            finally:
                if config_ok:
                    test_results.append("\n✅ Configuration is valid.")
                else:
                    test_results.append("\n❌ Configuration is not valid.")
                test_results.append("Configuration test completed.")

                # Update UI from main thread
                self.update_test_output("\n".join(test_results))
                QtCore.QMetaObject.invokeMethod(self.test_button, "setEnabled", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(bool, True))

        # Run tests in a separate thread to avoid blocking UI
        schedule_ui_task(run_tests())

    def update_test_output(self, text):
        """Thread-safe method to update test output."""
        QtCore.QMetaObject.invokeMethod(self.test_output, "setPlainText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, text))

    def get_config(self):
        try:
            new_config = json.loads(self.config_textarea.toPlainText())
            return new_config
        except json.JSONDecodeError:
            return self.config
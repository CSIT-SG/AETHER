from PyQt5 import QtWidgets

class CustomPromptDialog(QtWidgets.QDialog):
    """Dialog for getting custom user advice for re-annotation."""
    
    def __init__(self, parent=None):
        super(CustomPromptDialog, self).__init__()
        self.setWindowTitle("Re-annotate with Custom Prompt")
        self.setMinimumSize(600, 400)
        self.user_advice = ""
        
        layout = QtWidgets.QVBoxLayout()
        
        # Header
        header_label = QtWidgets.QLabel("Provide advice or feedback for re-annotating this function:")
        header_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        # Instructions
        info_label = QtWidgets.QLabel("You can describe what you think is wrong with the current analysis, or provide specific guidance for improvement. Use the suggestion buttons below for common scenarios.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("margin-bottom: 10px;")
        layout.addWidget(info_label)
        
        # Suggestion buttons section
        suggestions_label = QtWidgets.QLabel("Quick suggestions (hover over buttons to preview):")
        suggestions_label.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
        layout.addWidget(suggestions_label)
        
        # Create suggestion buttons in a grid layout
        suggestions_layout = QtWidgets.QGridLayout()
        suggestions_layout.setContentsMargins(0, 0, 0, 0)  # Remove padding around grid
        suggestions_layout.setSpacing(5)  # Small spacing between buttons only
        
        suggestions = [
            ("More Comments", "Try again. Focus on this function and give more comments."),
            ("Wrong Analysis", "The analysis is completely wrong. Re-analyse from first principles, assuming that all existing variable and function names cannot be trusted. You must do a fresh analysis yourself without using the names as guidance because they may be wrong."),
            ("Focus on Algorithms", "Focus on the algorithms and data structures used in this function. Provide detailed comments about the logic flow and computational steps."),
            ("Network/IO Focus", "This function appears to handle network communication or I/O operations. Focus on identifying protocols, data formats, and communication patterns."),
            ("Cryptography Focus", "This function appears to involve cryptographic operations. Focus on identifying encryption methods, key handling, and security-related operations."),
            ("File Operations", "This function appears to handle file operations. Focus on file formats, parsing logic, and data processing workflows."),
            ("Memory Management", "Focus on memory allocation, buffer management, and potential security implications like buffer overflows or memory corruption."),
            ("Error Handling", "Pay special attention to error handling paths, validation checks, and failure scenarios in this function."),
        ]
        
        # Arrange buttons in a 2-column grid
        for i, (button_text, suggestion_text) in enumerate(suggestions):
            row = i // 2
            col = i % 2
            
            btn = QtWidgets.QPushButton(button_text)
            btn.setToolTip(f"Click to use: {suggestion_text}")
            btn.clicked.connect(lambda checked, text=suggestion_text: self.use_suggestion(text))
            btn.setMaximumWidth(250)
            suggestions_layout.addWidget(btn, row, col)
        
        suggestions_widget = QtWidgets.QWidget()
        suggestions_widget.setLayout(suggestions_layout)
        suggestions_widget.setContentsMargins(0, 0, 0, 0)  # Remove padding around widget
        layout.addWidget(suggestions_widget)
        
        # Text area for user advice
        self.advice_text = QtWidgets.QTextEdit()
        self.advice_text.setPlaceholderText("e.g., 'The function appears to be parsing a configuration file, not handling network data as currently annotated. Focus on file I/O operations.'")
        self.advice_text.setMinimumHeight(120)
        layout.addWidget(self.advice_text)
        
        # Add clear button for text area
        text_controls_layout = QtWidgets.QHBoxLayout()
        self.clear_text_button = QtWidgets.QPushButton("Clear Text")
        self.clear_text_button.clicked.connect(self.clear_text)
        self.clear_text_button.setMaximumWidth(100)
        text_controls_layout.addWidget(self.clear_text_button)
        text_controls_layout.addStretch()
        layout.addLayout(text_controls_layout)
        
        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        button_layout.addStretch()
        
        self.reannotate_button = QtWidgets.QPushButton("Re-annotate")
        self.reannotate_button.setDefault(True)
        self.reannotate_button.clicked.connect(self.accept)
        button_layout.addWidget(self.reannotate_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def use_suggestion(self, suggestion_text):
        """Pre-populate the text area with the selected suggestion."""
        current_text = self.advice_text.toPlainText().strip()
        
        if current_text:
            # If there's already text, append the suggestion
            self.advice_text.setPlainText(current_text + "\n\n" + suggestion_text)
        else:
            # If empty, just set the suggestion
            self.advice_text.setPlainText(suggestion_text)
        
        # Move cursor to end and give focus to text area
        cursor = self.advice_text.textCursor()
        cursor.movePosition(cursor.End)
        self.advice_text.setTextCursor(cursor)
        self.advice_text.setFocus()
    
    def clear_text(self):
        """Clear the text area."""
        self.advice_text.clear()
        self.advice_text.setFocus()
    
    def get_user_advice(self):
        return self.advice_text.toPlainText().strip()

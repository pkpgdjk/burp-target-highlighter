from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import re
from java.awt import BorderLayout, FlowLayout, Color, Dimension
from javax.swing import (JPanel, JTextArea, JButton, JScrollPane, JLabel, JTextField, BorderFactory, 
                        JComboBox, JSeparator, BoxLayout, JOptionPane)

class TargetConfig:
    def __init__(self, panel, remove_callback):
        self.panel = panel
        self.noteField = JTextField(30)
        self.apiListsArea = JTextArea(4, 20)
        self.colorComboBox = JComboBox(['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray'])
        self.colorComboBox.setSelectedItem('orange')  # Default to orange
        self.removeButton = JButton('Remove', actionPerformed=lambda event: remove_callback(self))
        self.build_ui()
    
    def build_ui(self):
         # Center panel for Note, API lists, and Color selection
        centerPanel = JPanel(BorderLayout())
        
        
        notePanel = JPanel(FlowLayout(FlowLayout.LEADING))
        noteLabel = JLabel("Note:")
        notePanel.add(noteLabel)
        notePanel.add(self.noteField)

        colorPanel = JPanel(FlowLayout(FlowLayout.LEADING))
        colorLabel = JLabel("Select Highlight Color:")
        colorPanel.add(colorLabel)
        colorPanel.add(self.colorComboBox)
        
         # Note and color panels added
        noteColorPanel = JPanel(BorderLayout())
        noteColorPanel.add(notePanel, BorderLayout.NORTH)
        noteColorPanel.add(colorPanel, BorderLayout.SOUTH)

        apiListPanel = JPanel(BorderLayout())
        self.apiListsArea.setText(
"""
[method] [url] {} for parameter
Example: 
GET https://example.com/order/{orderId}/items/{itemId}
""".strip())  # Default text added
        scrollPane = JScrollPane(self.apiListsArea)
        apiListLabel = JLabel("API Lists:")
        apiListPanel.add(apiListLabel, BorderLayout.NORTH)
        apiListPanel.add(scrollPane, BorderLayout.CENTER)

        removeButtonPanel = JPanel(FlowLayout(FlowLayout.TRAILING))
        removeButtonPanel.add(self.removeButton)
        
        centerPanel.add(noteColorPanel, BorderLayout.NORTH)
        centerPanel.add(apiListPanel, BorderLayout.CENTER)
        centerPanel.add(removeButtonPanel, BorderLayout.AFTER_LAST_LINE)
        
        
       # Main panel setup with Border layout for flexibility
        # self.panel = JPanel(BorderLayout(5, 5))
        self.panel.add(centerPanel, BorderLayout.CENTER)
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # self.panel.add(notePanel, BorderLayout.NORTH)
        # self.panel.add(colorPanel, BorderLayout.NORTH)     # Moved color panel to the bottom
        # self.panel.add(apiListPanel, BorderLayout.CENTER)  # Corrected placement of API lists panel
        # self.panel.add(buttonPanel, BorderLayout.AFTER_LAST_LINE)


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def extensionName(self):
        return "Target Highlighter"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.extensionName())
        
        self.mainPanel = JPanel()
        self.mainPanel.setLayout(BoxLayout(self.mainPanel, BoxLayout.Y_AXIS))
        
        controlPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.addListButton = JButton(' + ', actionPerformed=self.add_list)
        self.saveButton = JButton('Save Targets', actionPerformed=self.save_targets)
        controlPanel.add(self.addListButton)
        controlPanel.add(self.saveButton)
        
        self.mainPanel.add(controlPanel)
        
        self.configs = []
        self.add_list(None)  # Start with one configuration by default

        # Wrap the main panel in a JScrollPane
        self.scrollPane = JScrollPane(self.mainPanel)
        
        # Add the scroll pane to the UI
        self.uiContainer = JPanel(BorderLayout())
        self.uiContainer.add(self.scrollPane, BorderLayout.CENTER)

        # Add the UI container to the tab
        callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        print(self.extensionName() + " Loaded")

    def getTabCaption(self):
        return self.extensionName()

    def getUiComponent(self):
        return self.uiContainer

    def add_list(self, event):
        def remove_callback(config):
            self.remove_config(config)
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
        if self.configs:
            separator = JSeparator(JSeparator.HORIZONTAL)
            configPanel.add(separator)
        config = TargetConfig(configPanel, remove_callback)
        self.configs.append(config)
        self.mainPanel.add(configPanel)
        self.mainPanel.revalidate()
        self.mainPanel.repaint()

    def remove_config(self, config):
        self.configs.remove(config)
        self.mainPanel.remove(config.panel)
        self.mainPanel.revalidate()
        self.mainPanel.repaint()

    def save_targets(self, event):
        for config in self.configs:
            entries = config.apiListsArea.getText().split('\n')
            color = config.colorComboBox.getSelectedItem()
            note = config.noteField.getText()
            print("Config saved: Color={}, Note='{}', Entries={}".format(color, note, entries))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY and messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = self.normalize_url(str(request_info.getUrl()))
            method = request_info.getMethod()
            print("Processing request: URL={}, Method={}".format(url, method))
            for config in self.configs:
                entries = config.apiListsArea.getText().split('\n')
                for entry in entries:
                    if entry.strip():
                        parsed_entry = self.parse_entry(entry)
                        print(re.search(parsed_entry['pattern'], url))
                        if parsed_entry['method'] == method and re.search(parsed_entry['pattern'], url):
                            print("Match found: Method={}, Pattern={}".format(parsed_entry['method'], parsed_entry['pattern']))
                            messageInfo.setHighlight(config.colorComboBox.getSelectedItem())
                            messageInfo.setComment(config.noteField.getText())
                            break

    def normalize_url(self, url):
        return re.sub(r':443(?=/|$)', '', re.sub(r':80(?=/|$)', '', url))

    def parse_entry(self, entry):
        parts = entry.split(' ', 1)
        method = parts[0].strip().upper()
        url_pattern = parts[1].strip()
        url_pattern = re.sub(r'\\\{[^\}]*\\\}', r'[^/]+', re.escape(url_pattern))  # Replace placeholders
        return {'method': method, 'pattern': "^" + url_pattern}



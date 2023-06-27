from burp import IBurpExtender, IContextMenuFactory, ITab, IParameter
import sys
from javax.swing import JPanel, JLabel, JButton, JMenuItem
from java.awt.event import ActionListener
from javax.swing import JFileChooser
from threading import Thread
from javax.swing import JPanel, JLabel, JButton, JCheckBox
from java.awt import FlowLayout
from javax.swing.border import TitledBorder
import json
import urlparse

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("ParaForge")
        callbacks.printOutput("Author: Sourav Kalal")
        callbacks.printOutput("Version: 0.1")
        callbacks.printOutput("GitHub - https://github.com/Anof-cyber/ParaForge")
        callbacks.registerContextMenuFactory(self)
        self.unique_parameters = set()
        self.store_endpoints = set()

        self.tab = JPanel()
        self.tab.setLayout(None)
        self.output_label = JLabel("Select the output directory:")
        self.output_label.setBounds(10, 10, 200, 20)
        self.tab.add(self.output_label)

        self.select_button = JButton("Output Directory", actionPerformed=self.selectDirectory)
        self.select_button.setBounds(10, 40, 150, 30)
        self.tab.add(self.select_button)

        self.path_label = JLabel()
        self.path_label.setBounds(10, 80, 400, 20)
        self.tab.add(self.path_label)
        self.selectedpath = None



        parameter_section = JPanel()
        parameter_section.setBorder(TitledBorder("Select the type of parameter to save"))
        parameter_section.setBounds(10, 120, 400, 150)
        parameter_section.setLayout(FlowLayout())

        self.cookie_checkbox = JCheckBox("Cookie Parameter")
        self.query_checkbox = JCheckBox("Query Parameter")
        self.form_checkbox = JCheckBox("Form Body Parameter")
        self.json_checkbox = JCheckBox("JSON Parameter")
        self.response_json_checkbox = JCheckBox("Response JSON Parameter")
        parameter_section.add(self.cookie_checkbox)
        parameter_section.add(self.query_checkbox)
        parameter_section.add(self.form_checkbox)
        parameter_section.add(self.json_checkbox)
        parameter_section.add(self.response_json_checkbox)

        self.tab.add(parameter_section)

        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "ParaForge"

    def getUiComponent(self):
        return self.tab

    def selectDirectory(self, event):
        file_chooser = JFileChooser()
        file_chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        result = file_chooser.showOpenDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            selected_directory = file_chooser.getSelectedFile()
            self.path_label.setText("Selected directory: " + selected_directory.getAbsolutePath())
            self.selectedpath = selected_directory.getAbsolutePath()
        else:
            self.path_label.setText("No directory selected")
            self.selectedpath = None



    
    def createMenuItems(self,invocation):

        context = invocation.getInvocationContext()
       
        menu_list = []
        if str(context) != "4":
            menu_list.append(JMenuItem("Save Parameters", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.parse_all_request_param, args=(inv,)).start()))
            menu_list.append(JMenuItem("Save URI Endpoint", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.parse_all_request_endpoint, args=(inv,)).start()))

        else:
            menu_list.append(JMenuItem("Save Parameters", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.parsesitemap_param, args=(inv,)).start()))
            menu_list.append(JMenuItem("Save URI Endpoint", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.parsesitemap_endpoint, args=(inv,)).start()))

      
        return menu_list


    def parsesitemap_param(self,invocation):

        sitemap = self.callbacks.getSiteMap(None)
        self.createparamter(sitemap)
        self.store_data_to_file('/parameter.txt',self.unique_parameters)
        self.unique_parameters.clear()

    def parse_all_request_param(self,invocation):
        reqRes = invocation.getSelectedMessages()
        self.createparamter(reqRes)
        self.store_data_to_file('/parameter.txt',self.unique_parameters)
        self.unique_parameters.clear()

    
    def parsesitemap_endpoint(self,invocation):

        sitemap = self.callbacks.getSiteMap(None)
        
        self.createendpoint(sitemap)
        self.store_data_to_file('/endpoint.txt',self.store_endpoints)
        self.store_endpoints.clear()

    def parse_all_request_endpoint(self,invocation):
        reqRes = invocation.getSelectedMessages()
        
        self.createendpoint(reqRes)
        self.store_data_to_file('/endpoint.txt',self.store_endpoints)
        self.store_endpoints.clear()


    def createendpoint(self,reqRes):
        
        if not str(self.selectedpath) == "None":
            
            
            for items in reqRes:

                request_url = self.helpers.analyzeRequest(items).getUrl().toString()
                
                
                parsed_url = urlparse.urlparse(request_url)
                path_segments = parsed_url.path.split("/")
                
                
                for segment in path_segments:
                    endpoint = "/" + segment
                    self.store_endpoints.add(endpoint)
                


    def createparamter(self,reqRes):
        if not str(self.selectedpath) == "None":

            for items in reqRes:

                parameters = self.helpers.analyzeRequest(items).getParameters()

                gettingrequest = items.getRequest()
                req = self.helpers.analyzeRequest(items)
                requestinst = self.helpers.bytesToString(gettingrequest)
                getody = req.getBodyOffset()
                body = requestinst[getody:len(requestinst)]

                response = items.getResponse()

                if response is not None and len(response) != 0:

                    response_info = self.helpers.analyzeResponse(response)
                    response_string = self.helpers.bytesToString(response)
                    body_offset = response_info.getBodyOffset()
                    response_body = response_string[body_offset:]

                    self.statedminetype = response_info.getStatedMimeType()
                    self.getInferredMimeType = response_info.getInferredMimeType()


                for param in parameters:

                    if self.query_checkbox.isSelected() and param.getType() == IParameter.PARAM_URL:
                        self.unique_parameters.add(param.getName())


                    if self.cookie_checkbox.isSelected() and param.getType() == IParameter.PARAM_COOKIE:
                        self.unique_parameters.add(param.getName())


                    if self.form_checkbox.isSelected() and param.getType() == IParameter.PARAM_BODY:
                        self.unique_parameters.add(param.getName())

                    if self.json_checkbox.isSelected() and param.getType() == IParameter.PARAM_JSON:

                        
                        try:
                            json_object = json.loads(body)
                            self.process_response_body(json_object)
                        except ValueError:
                            pass
                        

                    if self.response_json_checkbox.isSelected() and response_body:
                        if self.statedminetype == "JSON" or self.getInferredMimeType == "JSON":

                            try:
                                json_object = json.loads(response_body)
                                self.process_response_body(json_object)
                            except ValueError:
                                pass
                        
            
        
                

    def process_response_body(self, json_data):
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                self.unique_parameters.add(key)
                self.process_response_body(value)
        elif isinstance(json_data, list):
            for item in json_data:
                self.process_response_body(item)



    def store_data_to_file(self,filename,data):
        file_path = self.selectedpath + filename
       
        with open(file_path, "a") as file:
            for param in data:
                file.write(param + "\n")


   
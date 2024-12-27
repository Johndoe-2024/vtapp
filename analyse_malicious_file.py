## Author:       John Toor
## Script Name:  Analyse malicious file
## Start Date:   01/11/2024
## End Date:     --/--/----
## Purpose:      To seaching malicious files with Virus Total
## Version:      1.0
## Python:       3.9.7
## OS:           Windows 10

# Import libraries

import tkinter as tk
from tkinter import messagebox
import requests
import base64 
import json  # Import json to convert json to string
import var_api # Import var_api.py file 

class VirusTotalApp:
    def __init__(self):
        self.apiKey = var_api.ExternalApiKey # Enter your personnal API Key

    def scan_url(self, UrlToAnalyse):

        # Need to encode URL in base64
        urlId = base64.urlsafe_b64encode(UrlToAnalyse.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{urlId}"

        # Construct header with API Key
        headers = {
            "accept": "application/json",
            "x-apikey": self.apiKey
        }

        response = requests.get(url, headers=headers)
        # Copy result in file
        if response.status_code == 200:
            with open("result_malicious.log", "w") as F_malicious:
                json.dump(response.json(), F_malicious, indent=4) # Convert json response to string

                return response.json()  # Return the json response
        else:
            print(response.text)

class GUIApp:
    def __init__(self, root, vTotalApp):
        self.root = root
        self.vTotalApp = vTotalApp
        
        self.root.title("Virus Total App")
        self.root.geometry("500x500")

        self.url_entry = tk.Entry(self.root, width=50)
        self.url_entry.pack(pady=10)

        self.scan_button = tk.Button(self.root, text="Analyser URL", command=self.on_click)
        self.scan_button.pack(pady=10)

        self.result_text = tk.Text(self.root, wrap=tk.WORD, width=70, height=20)
        self.result_text.pack(pady=10)

    def on_click(self):
        urlToScan = self.url_entry.get()

        result = self.vTotalApp.scan_url(urlToScan)
        self.result_text.insert(tk.END, str(result) + "\n")        

## Main function

app1 = VirusTotalApp() # Create an instance of VirusTotalApp
root = tk.Tk() # Create a tkinter window

guiApp1 = GUIApp(root, app1) # Create an instance of GUIApp

root.mainloop() # Start the GUI
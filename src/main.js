const { Plugin, PluginSettingTab, Setting, Notice, Modal } = require('obsidian');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const os = require('os');
const platform = process.platform;


function curlRequest({ url, method = 'GET', headers = {} }) {
  // Construct the header part of the curl command
  let headerStr = '';
  for (const [key, value] of Object.entries(headers)) {
      headerStr += `-H "${key}: ${value}" `;
  }

  // Create the curl command
  const curlCmd = `curl -X ${method} ${headerStr} "${url}"`;

  // Execute the curl command
  return new Promise((resolve, reject) => {
      exec(curlCmd, (error, stdout, stderr) => {
          if (error) {
              console.error(`exec error: ${error}`);
              reject({ code: error.code, error: stderr });
          } else {
              console.log(`stdout: ${stdout}`);
              resolve({ code: 0, content: stdout });
          }
      });
  });
}

function powershellRequest({ url, method = 'GET', headers = {} }) {
  // Construct the header part of the PowerShell command
  let headerStr = '';
  for (const [key, value] of Object.entries(headers)) {
      headerStr += `-Headers @{${key}='${value}'} `;
  }

  // Create the PowerShell command
  const psCmd = `powershell -Command "(Invoke-WebRequest -Uri '${url}' -Method ${method} ${headerStr} -UseBasicParsing).Content"`;

  // Execute the PowerShell command
  return new Promise((resolve, reject) => {
      exec(psCmd, { shell: 'powershell.exe' }, (error, stdout, stderr) => {
          if (error) {
              console.error(`exec error: ${error}`);
              reject({ code: error.code, error: stderr });
          } else {
              console.log(`stdout: ${stdout}`);
              resolve({ code: 0, content: stdout });
          }
      });
  });
}

function identifyInput(input) {
  // Regular expression for MD5, SHA1, SHA256 hashes
  const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

  // Regular expression for IPv4 addresses
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  // Regular expression for domains
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;

  // Check if input matches hash patterns (MD5, SHA1, SHA256)
  if (hashRegex.test(input)) {
      return "files";
  }

  // Check if input matches IPv4 pattern
  if (ipv4Regex.test(input)) {
      return "ip_addresses";
  }

  // Check if input matches domain pattern
  if (domainRegex.test(input)) {
      return "domains";
  }

  // If none of the above, return unknown
  return "unknown";
}

function convertEpochToISO(obj) {
  function isEpoch(num) {
      // Check if the number is in the range of common epoch timestamps (specifically targeting recent timestamps)
      // This range covers dates from around 2001 to 2030
      return num > 1000000000 && num < 2000000000;
  }

  function convert(obj) {
      for (let key in obj) {
          if (obj.hasOwnProperty(key)) {
              if (typeof obj[key] === 'object') {
                  convert(obj[key]); // Recursively search for nested objects
              } else if (typeof obj[key] === 'number' && isEpoch(obj[key])) {
                  var newDate = new Date(obj[key] * 1000).toISOString(); // Convert epoch to ISO date-time string
                  obj[key] = newDate.replace(/_/g, '-').replace('T', ' ').replace(/(\d{2})_(\d{2})_(\d{2})/, '$1:$2:$3').split('.')[0];

              }
          }
      }
  }

  const clonedObj = JSON.parse(JSON.stringify(obj)); // Clone the original object to avoid mutating it
  convert(clonedObj);
  return clonedObj;
}

class VirusTotalEnrichPlugin extends Plugin {
    settings = {
        apiKey: '',
        includePageType: true,
        pageType: 'indicator',
        customFields: { 
          'name': 'attributes.meaningful_name', 
          'first_submission_date': 'attributes.first_submission_date', 
          'creation_date': 'attributes.creation_date', 
          'filetype': 'attributes.type_description', 
          'size': 'attributes.size', 
          'md5': 'attributes.md5', 
          'sha1': 'attributes.sha1', 
          'sha256': 'attributes.sha256', 
          'magic': 'attributes.magic', 
          'tlsh': 'attributes.tlsh', 
          'ssdeep': 'attributes.ssdeep', 
        }
    };

    onload() {
        console.log('Loading VirusTotal Enrichment plugin');
        this.loadSettings();

        // Register the settings tab
        this.addSettingTab(new SettingTab(this.app, this));

        // Register the about modal command
        this.addCommand({
            id: 'open-about-modal',
            name: 'Open About Page',
            callback: () => this.openAboutModal()
        });

        // Register the enrich command
        this.addCommand({
            id: 'enrich-current-note',
            name: 'Enrich Current Note',
            callback: () => {
                const enricher = new EnrichIndicator(this.app, this);
                enricher.enrichCurrentNote();
            }
        });
    }

    onunload() {
        console.log('Unloading plugin');
    }
    async loadSettings() {
        try {
          this.settings = Object.assign({}, this.settings, await this.loadData());
      } catch (error) {
          console.error('Failed to load settings:', error);
          new Notice('Error loading settings.');
      }
    }
    async saveSettings() {
      try {
          await this.saveData(this.settings);
          new Notice('Settings saved successfully!');
      } catch (error) {
          console.error('Failed to save settings:', error);
          new Notice('Error saving settings.');
      }
  }
    openAboutModal() {
        // Simple modal to show about information
        new AboutModal(this.app).open();
    }
}

class SettingTab extends PluginSettingTab {
    plugin;

    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
      const {containerEl} = this;
      containerEl.empty();
      containerEl.createEl('h2', {text: 'Settings for Virus Total Enrichment'});

      new Setting(containerEl)
          .setName('API Key')
          .setDesc('Enter your API key here.')
          .addText(text => text
              .setValue(this.plugin.settings.apiKey)
              .onChange(async (value) => {
                  this.plugin.settings.apiKey = value;
                  await this.plugin.saveSettings();
              }));

      new Setting(containerEl)
          .setName('Include Page Type')
          .setDesc('Toggle whether to include the Page Type property.')
          .addToggle(toggle => toggle
              .setValue(this.plugin.settings.includePageType)
              .onChange(async (value) => {
                  this.plugin.settings.includePageType = value;
                  await this.plugin.saveSettings();
              }));

      new Setting(containerEl)
          .setName('Page Type Value')
          .setDesc('Set the value for the Page Type property.')
          .addText(text => text
              .setValue(this.plugin.settings.pageType)
              .onChange(async (value) => {
                  this.plugin.settings.pageType = value;
                  await this.plugin.saveSettings();
              }));

      new Setting(containerEl)
          .setName('Custom Fields')
          .setDesc('Add custom key-value pairs for enrichment.')
          .addTextArea(text => text
              .setValue(JSON.stringify(this.plugin.settings.customFields, null, 2))
              .onChange(async (value) => {
                  try {
                      this.plugin.settings.customFields = JSON.parse(value);
                      await this.plugin.saveSettings();
                  } catch (error) {
                      new Notice('Invalid JSON format for custom fields.');
                  }
              }));
  }
}

class AboutModal extends Modal {
  constructor(app) {
      super(app);
  }

  onOpen() {
      const {contentEl} = this;
      contentEl.empty();

      contentEl.createEl('h1', { text: 'VirusTotal Enrichment Plugin' });

      contentEl.createEl('img', {
          attr: {
              src: 'path_to_your_image.png',
              alt: 'Plugin Icon'
          },
          cls: 'modal-icon'
      });

      contentEl.createEl('p', { text: 'This plugin enhances your Obsidian notes by fetching and displaying data from VirusTotal based on the content of your notes.\nNotes will be enriched with properties as well as entire JSON digest as an appendix to the note. This plugin was desgined to, hopefully, be easy to use with dataview for cool queries.' });

      contentEl.createEl('h3', { text: 'Developed by:' });
      contentEl.createEl('p', { text: 'tisf' });

      contentEl.createEl('h3', { text: 'GitHub Repository:' });
      contentEl.createEl('a', {
          text: 'View on GitHub',
          href: 'https://github.com/ytisf/virustotal-enrich'
      });

      contentEl.createEl('h3', { text: 'Dataview Examples:' });
      contentEl.createEl('a', {
          text: 'View on GitHub',
          href: 'https://github.com/ytisf/virustotal-enrich/dataview_examples.md'
      });

      contentEl.createEl('h3', { text: 'End-User License Agreement (EULA):' });
      contentEl.createEl('a', {
          text: 'Read EULA',
          href: 'https://github.com/ytisf/virustotal-enrich/blob/main/LICENSE'
      });

      contentEl.createEl('p', { text: 'For more information and updates, follow the repository on GitHub.' });

      contentEl.createEl('button', {
          text: 'Close',
          cls: 'mod-cta',
          type: 'button',
          onclick: () => {
              this.close();
          }
      });
  }

  onClose() {
      let {contentEl} = this;
      contentEl.empty();
  }
}

class EnrichIndicator {
  constructor(app, plugin) {
      this.app = app;
      this.plugin = plugin;
  }

  createYamlPreamble(jsonData) {
    const escapeYamlString = (str) => {
        // Replace problematic characters with underscore and escape double quotes
        let sanitized = str.replace(/[:\{\}\[\],&*#?|\-<>=!%@\\]/g, '_').replace(/"/g, '\\"');
        // Wrap the sanitized string in double quotes
        return `"${sanitized}"`;
    };

    const recurseObject = (obj, indent = '') => {
        let yamlContent = '';
        for (const key in obj) {
            if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                yamlContent += `${indent}${key}:\n`;
                yamlContent += recurseObject(obj[key], indent + '  ');
            } else if (Array.isArray(obj[key])) {
                yamlContent += `${indent}${key}:\n`;
                obj[key].forEach((item) => {
                    if (typeof item === 'object' && item !== null) {
                        yamlContent += `${indent}  - `;
                        yamlContent += recurseObject(item, indent + '    ').trim();
                        yamlContent += '\n';
                    } else {
                        const itemStr = String(item);
                        if (itemStr.length <= 513) {
                            yamlContent += `${indent}  - ${escapeYamlString(itemStr)}\n`;
                        }
                    }
                });
            } else {
                const valueStr = String(obj[key]);
                if (valueStr.length <= 513) {
                    yamlContent += `${indent}${key}: ${escapeYamlString(valueStr)}\n`;
                }
            }
        }
        return yamlContent;
    };

    return `\n${recurseObject(jsonData)}---`;
  }

  enrichCurrentNote() {
    
    let httpFunction;
    if (platform === 'win32') {
      httpFunction = powershellRequest;
    } else {
      httpFunction = curlRequest;
    }


    const activeLeaf = this.app.workspace.activeLeaf;
    if (activeLeaf) {
        const editor = activeLeaf.view.sourceMode.cmEditor;
        const content = editor.getValue();
        const noteTitle = this.app.workspace.getActiveFile().basename;

        var search_type = identifyInput(noteTitle);
        var url_to_get = `https://www.virustotal.com/api/v3/${search_type}/${noteTitle}`;

        // Use the curlRequest function to send data to an API
        httpFunction({
            url: url_to_get,
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'x-apikey': `${this.plugin.settings.apiKey}`
            }
        }).then(response => {
            // Check if response has content and try to parse it
            if (response && response.content) {
              try {
                // Attempt to parse the content string into JSON
                // var parsedContent = JSON.parse(response.content)["data"];
                    var fixed_content = convertEpochToISO(JSON.parse(response.content)["data"])
                    var data = JSON.stringify(fixed_content, null, 2);
                } catch (error) {
                    console.error('Error parsing JSON from content:', error);
                    var data = '{"error": "Failed to parse content"}';
                    new Notice(`Request failed: ${response.content}`);
                    return;
                }
            } else {
                console.error('Invalid or missing data in response:', response);
                var data = '{"error": "No content found"}';
                new Notice(`Request failed: ${response.content}`);
                return;
            }
            
            // Got Response - Now process it:
            var bottom_appendix = '\n\n\n\n\n#### Appendix - VirusTotal Output\n```json\n' + data + '\n```\n\n';

            // Ensure the cursor is at the bottom and append the data
            editor.setCursor(editor.lineCount(), 0);
            editor.replaceSelection(bottom_appendix);

            // Parse the content JSON and create YAML preamble
            var now = new Date().toISOString().replace('T', ' ').substring(0, 19);
            var new_content = editor.getValue();
            var yamlPreamble = "---\n";
            if (this.plugin.settings.includePageType) {
                yamlPreamble += `pageType: ${this.plugin.settings.pageType}\n`;
            }
            // Handle custom fields
            Object.entries(this.plugin.settings.customFields).forEach(([key, path]) => {
              const value = _.get(JSON.parse(data), path, 'Not available');
              yamlPreamble += `${key}: ${value}\n`;
            });
            yamlPreamble = `${yamlPreamble}main_value: ${noteTitle}\n`;
            yamlPreamble = `${yamlPreamble}enrichment_date: ${now}\n`;
            yamlPreamble = `${yamlPreamble}adversary: \n`;
            yamlPreamble = `${yamlPreamble}nation-state: \n`;
            yamlPreamble = `${yamlPreamble}variant: \n`;
            yamlPreamble = `${yamlPreamble}campaign: \n`;
            yamlPreamble = `${yamlPreamble}main_comment: \n`;
            yamlPreamble = `${yamlPreamble}toolset: \n`;
            
            yamlPreamble += this.createYamlPreamble(fixed_content);
           
            var updatedContent = yamlPreamble + "\n" + new_content;
            editor.setValue(updatedContent);

            new Notice('Note enriched successfully.');

        }).catch(error => {
            console.error('Failed to enrich note:', error);
            new Notice('Failed to enrich note.');
        });
    } else {
        new Notice('No active note found.');
    }
  }
}


module.exports = VirusTotalEnrichPlugin;

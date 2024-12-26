import * as vscode from "vscode";
import { Section } from "./parsers/file/section";
import { PacketDetailsTree, Node } from "./packetdetailstree";
import { ProtocolAnalysisTree, ProtocolNode } from "./protocolanalysis";
import { pcapViewerDocument } from "./pcapviewer";

export class PacketDetailsProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "packetDetails.data"; //"packetDetails.detailsView";

  private _view?: vscode.WebviewView;
  private _extensionUri: vscode.Uri;
  private _section?: Section;
  private _currentDocument?: pcapViewerDocument;

  constructor(public readonly context: vscode.ExtensionContext) {
    this._extensionUri = context.extensionUri;
  }

  public checkDispose(document?: pcapViewerDocument) {
    if (document === this._currentDocument) {
      this._section = undefined;

      if (this._view !== undefined)  {
        this._view.webview.html = this._getHtmlForWebview(
          this._view.webview,
          this._section
        );
      }
    }
  }

  public refresh(document?: pcapViewerDocument) {
    if (this._view === undefined) {
      return;
    }

    this._currentDocument = document;

    if (document !== undefined) {
      if (document.selectedSection !== -1) {
        this._section = document.sections[document.selectedSection];

        this._view.webview.html = this._getHtmlForWebview(
          this._view.webview,
          this._section
        );

        new PacketDetailsTree(this, this._section.getProperties);
        return;
      }
    } 

    this._section = undefined;

    this._view.webview.html = this._getHtmlForWebview(
      this._view.webview,
      this._section
    );
  }

  public select(start: number, length:number) {
    if (this._view === undefined) {
      return;
    }

    this._view.webview.html = this._getHtmlForWebview(
      this._view.webview,
      this._section,
      start, length
    );

  }

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

  }

  private _getHtmlForWebview(webview: vscode.Webview, section?: Section, selectionStart: number = 0, selectionLength: number = 0) {
    const styleResetUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, "media", "reset.css"));
    const styleMainUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, "media", "main.css"));
		const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'main.js'));

    const nonce = getNonce();

    let strProperties = "";
    let strHex = "";
    let strASCII = "";
    let strIndex = "";
    let lines = 0;

    if (section !== undefined) {
      strHex = section.getHex;
      strASCII = section.getASCII;

      lines = strASCII.length / 8;

      if (selectionLength) {
        selectionStart -= section.packetStartOffset;
        let start = selectionStart * 3;
        let end = (selectionStart + selectionLength) * 3;
        strHex = strHex.slice(0, start) + `<span class="packet-selected">` + strHex.slice(start, end - 1) + `</span>` + strHex.slice(end - 1);
        start = selectionStart;
        end = selectionStart + selectionLength;
        strASCII = strASCII.slice(0, start) + `<span class="packet-selected">` + strASCII.slice(start, end) + `</span>` + strASCII.slice(end);
      }
    } else {
      strProperties = "Select a packet from a pcap file to view packet bytes here.";
      new PacketDetailsTree(this, [new Node("Select a packet from a pcap file to view packet details here.", "")]);
    }
  
    for (let i = 0; i < lines; i++) {
      strIndex += (i*8).toString(16).padStart(4, "0");
    }

    return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<link href="${styleResetUri}" rel="stylesheet">
				<link href="${styleMainUri}" rel="stylesheet">
				<title>Packet Details</title>
			</head>
			<body>
          <span class="packet-message">${strProperties}</span>
          <span class="packet-output">
            <span class="packet-index"> ${strIndex} </span>
            <span class="packet-hex"> ${strHex} </span>
            <span class="packet-ascii"> ${strASCII} </span>
          </span>
			</body>
			</html>`;
  }
}

function getNonce() {
  let text = "";
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

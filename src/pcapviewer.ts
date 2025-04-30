import * as vscode from 'vscode';
import { readFileSync } from 'fs';
import { Disposable, disposeAll } from './dispose';
import { PCAPNGSystemdJournalExportBlock, PCAPNGEnhancedPacketBlock, PCAPNGSimplePacketBlock, PCAPPacketRecord, Section } from "./parsers/file/section";
import { PacketDetailsProvider } from './packetdetails';
import { PacketDetailsTree } from './packetdetailstree';
import { ProtocolAnalysisTree, ProtocolNode } from './protocolanalysis';
import { FileContext } from './parsers/file/FileContext';



//#region pcapViewerDocument
	
enum AddressType {
	Hardware,
	IPv4,
	IPv6
}

export class pcapViewerDocument extends Disposable implements vscode.CustomDocument {

	static async create(
		uri: vscode.Uri
	): Promise<pcapViewerDocument | PromiseLike<pcapViewerDocument>> {
		const dataFile = uri;
		const fileData = await pcapViewerDocument.readFile(dataFile);
		return new pcapViewerDocument(uri, fileData);
	}

	private static async readFile(uri: vscode.Uri): Promise<Uint8Array> {
		if (uri.scheme === 'untitled') {
			return new Uint8Array();
		}
		return new Uint8Array(await vscode.workspace.fs.readFile(uri));
	}

	private readonly _uri: vscode.Uri;

	private _documentData: Uint8Array;
	private _sections: Array<Section> = [];
	public selectedSection: number = -1;
	public fc: FileContext;

	private constructor(
		uri: vscode.Uri,
		initialContent: Uint8Array,
	) {
		super();
		this._uri = uri;
		this._documentData = initialContent;

		let start = new Date();

		this.fc = new FileContext(this._documentData);

		let offset = 0;
		let packet;

		while(offset < this.fc.bytes.byteLength) {
			try {
				packet = Section.create(this.fc);
				this._sections.push(packet);
			} catch(e) {
				if (e instanceof Error) {
					console.log(`Exception rendering, call stack: ${e.stack}`);
				} else {
					console.log(`Exception rendering`);
				}
				break;
			}
			offset = packet.endoffset;
		}

		let finish = new Date();
		console.log(`Run time: ${((finish.getTime()-start.getTime())/1000.0)}`);
	}

	public get sections(): Array<Section> {
		return this._sections;
	}
	public get uri() { return this._uri; }

	public get documentData(): Uint8Array { return this._documentData; }

	private readonly _onDidDispose = this._register(new vscode.EventEmitter<void>());

	public readonly onDidDispose = this._onDidDispose.event;

	private readonly _onDidChange = this._register(new vscode.EventEmitter<{
		readonly label: string,
		undo(): void,
		redo(): void,
	}>());
	/**
	 * Fired to tell VS Code that an edit has occurred in the document.
	 *
	 * This updates the document's dirty indicator.
	 */
	public readonly onDidChange = this._onDidChange.event;

	/**
	 * Called by VS Code when there are no more references to the document.
	 *
	 * This happens when all editors for it have been closed.
	 */
	dispose(): void {
		this._onDidDispose.fire();
		super.dispose();
	}

	/**
	 * Called by VS Code when the user saves the document.
	 */
	async save(cancellation: vscode.CancellationToken): Promise<void> {
		await this.saveAs(this.uri, cancellation);
	}

	/**
	 * Called by VS Code when the user saves the document to a new location.
	 */
	async saveAs(targetResource: vscode.Uri, cancellation: vscode.CancellationToken): Promise<void> { 
		if (cancellation.isCancellationRequested || !targetResource.path.toLowerCase().endsWith(".txt")) { 
			return; 
		} 
		let textData:string = ""; 
		this._sections.forEach(s => { 
			textData += s.toString + "\n"; 
		}); 
		const encoder = new TextEncoder(); 
		await vscode.workspace.fs.writeFile(targetResource, encoder.encode(textData.trimEnd())); 
	} 

	/**
	 * Called by VS Code when the user calls `revert` on a document.
	 */
	async revert(_cancellation: vscode.CancellationToken): Promise<void> {
		return;
	}

	/**
	 * Called by VS Code to backup the edited document.
	 *
	 * These backups are used to implement hot exit.
	 */
	async backup(destination: vscode.Uri, cancellation: vscode.CancellationToken): Promise<vscode.CustomDocumentBackup> {
		await this.saveAs(destination, cancellation);

		return {
			id: destination.toString(),
			delete: async () => {
				try {
					await vscode.workspace.fs.delete(destination);
				} catch {
					// noop
				}
			}
		};
	}
}

//#region CustomEditorProvider
	
export class pcapViewerProvider implements vscode.CustomReadonlyEditorProvider<pcapViewerDocument> {

	private static newpcapViewerFileId = 1;
	private isFilter = false;
	private lastURI?:vscode.Uri = undefined;
	private lastNode?:ProtocolNode = undefined;

	public static register(context: vscode.ExtensionContext, details: PacketDetailsProvider): vscode.Disposable {
		vscode.commands.registerCommand("packetreader.pcap.new", () => {
			const workspaceFolders = vscode.workspace.workspaceFolders;
			if (!workspaceFolders) {
				vscode.window.showErrorMessage("Creating new files currently requires opening a workspace");
				return;
			}

			const uri = vscode.Uri.joinPath(workspaceFolders[0].uri, `new-${pcapViewerProvider.newpcapViewerFileId++}.pcap`)
				.with({ scheme: 'untitled' });

			vscode.commands.executeCommand('vscode.openWith', uri, pcapViewerProvider.viewType);
		});

		const provider = new pcapViewerProvider(context, details);
		vscode.commands.executeCommand('setContext', 'pcapviewer:isFilterMode', false);
		vscode.commands.registerCommand('packetanalysis.select', (uri, node) => provider.select(uri, node));
		vscode.commands.registerCommand('packetAnalysis.setFilterMode', () => provider.setFilterMode());
		vscode.commands.registerCommand('packetAnalysis.setHighlightMode', () => provider.setHighlightMode());

		return vscode.window.registerCustomEditorProvider(
			pcapViewerProvider.viewType,
			provider,
			{
				webviewOptions: {
					retainContextWhenHidden: true,
					enableFindWidget: true
				},
				supportsMultipleEditorsPerDocument: false,
			});
	}

	private static readonly viewType = "packetreader.pcap";

	/**
	 * Tracks all known webviews
	 */
	private readonly webviews = new WebviewCollection();

	constructor(
		private readonly _context: vscode.ExtensionContext,
		private readonly _details: PacketDetailsProvider
	) { 
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.showMAC', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showHardwareAddresses", !setting.get("showHardwareAddresses"), vscode.ConfigurationTarget.Global);
		}));
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.hideMAC', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showHardwareAddresses", !setting.get("showHardwareAddresses"), vscode.ConfigurationTarget.Global);
		}));
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.showTimeStamp', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showFullTimestamp", !setting.get("showFullTimestamp"), vscode.ConfigurationTarget.Global);
		}));
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.showTimeOffset', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showFullTimestamp", !setting.get("showFullTimestamp"), vscode.ConfigurationTarget.Global);
		}));
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.showComments', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showComments", !setting.get("showComments"), vscode.ConfigurationTarget.Global);
		}));
		_context.subscriptions.push(vscode.commands.registerCommand('packetAnalysis.hideComments', async () => {
			const setting = vscode.workspace.getConfiguration('networktools');
			setting.update("showComments", !setting.get("showComments"), vscode.ConfigurationTarget.Global);
		}));
	}

	public setFilterMode() {
		this.isFilter = !this.isFilter;
		vscode.commands.executeCommand('setContext', 'pcapviewer:isFilterMode', this.isFilter);

		if (this.lastURI !== undefined && this.lastNode !== undefined) {
			this.select(this.lastURI, this.lastNode);
		}
	}

	public setHighlightMode() {
		this.isFilter = !this.isFilter;
		vscode.commands.executeCommand('setContext', 'pcapviewer:isFilterMode', this.isFilter);

		if (this.lastURI !== undefined && this.lastNode !== undefined) {
			this.select(this.lastURI, this.lastNode);
		}
	}

	public async select(uri:vscode.Uri, node: ProtocolNode) {
		this.lastURI = uri;
		this.lastNode = node;

		for (let w of this.webviews.get(uri)) {
			let r = w.webview.postMessage({ command: 'customevent', filterMode: this.isFilter, data: node.items });
		}
	}

	async openCustomDocument(
		uri: vscode.Uri,
		openContext: { backupId?: string },
		_token: vscode.CancellationToken
	): Promise<pcapViewerDocument> {
		const document: pcapViewerDocument = await pcapViewerDocument.create(uri);

		const listeners: vscode.Disposable[] = [];

		listeners.push(document.onDidChange(e => {
			// Tell VS Code that the document has been edited by the use.
			this._onDidChangeCustomDocument.fire({
				document,
				...e,
			});
		}));
		
		document.onDidDispose(() => { 
			this._details.checkDispose(document);
			disposeAll(listeners);
			new ProtocolAnalysisTree(this._context, [], undefined);
		});

		return document;
	}

	private getAddressType(address:string):AddressType {
		const macpattern = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
		const ippattern = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;

		if (macpattern.exec(address)) {
			return AddressType.Hardware;
		} if (ippattern.exec(address)) {
			return AddressType.IPv4;
		} else {
			return AddressType.IPv6;
		}

	}

	private createAnalysisTree(document:pcapViewerDocument) {
		const elements = [
			new ProtocolNode("Clear selection", "", vscode.TreeItemCollapsibleState.None),
			new ProtocolNode("Interfaces", "", vscode.TreeItemCollapsibleState.Collapsed),
			new ProtocolNode("Protocols", "", vscode.TreeItemCollapsibleState.Expanded)
		];

		const ie = elements[1].children;
		for (let entry of document.fc.interfaces) {
			const arr: number[] = []; 
			for (let s of entry[1]) {
				arr.push(s.lineNumber);
			}
			ie.push(new ProtocolNode(entry[0], `${entry[1].length} ${entry[1].length > 1 ? "packets" : "packet"}`,vscode.TreeItemCollapsibleState.None, arr));
		}

		const pe = elements[2].children;
		for (let entry of [...document.fc.protocols].sort((a, b) => a[0].localeCompare(b[0]))) {
			const arr: number[] = []; 
			for (let s of entry[1]) {
				arr.push(s.lineNumber);
			}
			pe.push(new ProtocolNode(entry[0], `${entry[1].length} ${entry[1].length > 1 ? "packets" : "packet"}`,vscode.TreeItemCollapsibleState.None, arr));
		}

		const addresses = new ProtocolNode("Addresses", "", vscode.TreeItemCollapsibleState.Collapsed);
		elements.push(addresses);
		const ae = addresses.children;

		let mac = new ProtocolNode("Hardware", "", vscode.TreeItemCollapsibleState.Collapsed);
		ae.push(mac);
		let ipv4 = new ProtocolNode("IPv4", "", vscode.TreeItemCollapsibleState.Collapsed);
		ae.push(ipv4);
		// let ipv4pvt = new ProtocolNode("IPv4 Private", "", vscode.TreeItemCollapsibleState.Collapsed);
		// ae.push(ipv4pvt);
		// let ipv4int = new ProtocolNode("IPv4 Internet", "", vscode.TreeItemCollapsibleState.Collapsed);
		// ae.push(ipv4int);
		let ipv6 = new ProtocolNode("IPv6", "", vscode.TreeItemCollapsibleState.Collapsed);
		ae.push(ipv6);

		for (let entry of [...document.fc.addresses].sort((a, b) => a[0].localeCompare(b[0]))) {
			const arr: number[] = []; 
			for (let s of entry[1]) {
				arr.push(s.lineNumber);
			}
			let push = ae;
			switch (this.getAddressType(entry[0])) {
				case AddressType.Hardware: push = mac.children; break; 
				case AddressType.IPv4: push = ipv4.children; break; 
				case AddressType.IPv6: push = ipv6.children; break; 
			}
			push.push(new ProtocolNode(entry[0], `${entry[1].length} ${entry[1].length > 1 ? "packets" : "packet"}`,vscode.TreeItemCollapsibleState.None, arr));
		}

		const tree = new ProtocolAnalysisTree(this._context, elements, document);
	}

	async resolveCustomEditor(
		document: pcapViewerDocument,
		webviewPanel: vscode.WebviewPanel,
		_token: vscode.CancellationToken
	): Promise<void> {
		// Add the webview to our internal set of active webviews
		this.webviews.add(document.uri, webviewPanel);

		// Setup initial content for the webview
		webviewPanel.webview.options = {
			enableScripts: true,
		};

		webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, document);

		this.createAnalysisTree(document);

		vscode.workspace.onDidChangeConfiguration(data => {
			webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, document);
		});

		webviewPanel.webview.onDidReceiveMessage(data => {
			switch (data.type) {
				case 'packetSelected':
					{
						document.selectedSection = data.value;
						this._details.refresh(document);
						break;
					}
			}
		});

		webviewPanel.onDidChangeViewState(data => {
			const panel = data.webviewPanel;

			if(panel.visible) {
				this.createAnalysisTree(document);
			} else {
				new ProtocolAnalysisTree(this._context, [], undefined);
			}
			
			if(panel.visible && document.selectedSection !== -1) {
				this._details.refresh(document);
			} else {
				this._details.refresh(undefined);
			}
		});

		
	}

	private readonly _onDidChangeCustomDocument = new vscode.EventEmitter<vscode.CustomDocumentEditEvent<pcapViewerDocument>>();
	public readonly onDidChangeCustomDocument = this._onDidChangeCustomDocument.event;

	public saveCustomDocument(document: pcapViewerDocument, cancellation: vscode.CancellationToken): Thenable<void> {
		return document.save(cancellation);
	}

	public saveCustomDocumentAs(document: pcapViewerDocument, destination: vscode.Uri, cancellation: vscode.CancellationToken): Thenable<void> {
		return document.saveAs(destination, cancellation);
	}

	public revertCustomDocument(document: pcapViewerDocument, cancellation: vscode.CancellationToken): Thenable<void> {
		return document.revert(cancellation);
	}

	public backupCustomDocument(document: pcapViewerDocument, context: vscode.CustomDocumentBackupContext, cancellation: vscode.CancellationToken): Thenable<vscode.CustomDocumentBackup> {
		return document.backup(context.destination, cancellation);
	}

	//#endregion

	/**
	 * Get the static HTML used for in our editor's webviews.
	 */
	private getHtmlForWebview(webview: vscode.Webview, document: pcapViewerDocument): string {
		// Local path to script and css for the webview
		const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this._context.extensionUri, 'media', 'main.js'));
		const css = readFileSync(vscode.Uri.joinPath(this._context.extensionUri, 'media', 'vscode.css').with({scheme: 'vscode-resource'}).fsPath, "utf-8");

		let lineOutput: string = "";
		let lineNumberOutput: string = "";
		let lines: number = 0;
		let pktline: number = 1;

		document.sections.forEach((section) => {
			try {
				let _class = "";

				if (vscode.workspace.getConfiguration('networktools').get('showComments')) {
					if (section.comments.length) {
						for (const comment of section.comments) {
							if (comment.length) {
								lineNumberOutput += `<span></span>`;
								lineOutput += `<div class="comment" id="${lines}">// ${comment}</div>`;
							}
						}
					}
				}

				if (
					section instanceof PCAPNGEnhancedPacketBlock || 
					section instanceof PCAPPacketRecord ||
					section instanceof PCAPNGSimplePacketBlock ||
					section instanceof PCAPNGSystemdJournalExportBlock
				) {

					_class = ` class="numbered" data-ln="${pktline.toString().padStart(document.sections.length.toString().length, '&').replaceAll('&', '&nbsp;')}"`;
					pktline++;
				}

				lineNumberOutput += `<span${_class}"></span>`;
				lineOutput += `<div${_class} id="${lines}">${section.toString}</div>`;
				section.lineNumber = lines;
				lines++;
			} catch (e)
			{
				if (e instanceof Error) {
					console.log(`Exception rendering, call stack: ${e.stack}`);
				} else {
					console.log(`Exception rendering`);
				}
			}
		});

		const nonce = getNonce();
		return /* html */`
			<!DOCTYPE html>
			<html lang="en" >
			<head>
				<meta charset="UTF-8">

				<!--
				Use a content security policy to only allow loading images from https or from our extension directory,
				and only allow scripts that have a specific nonce.
				-->
				<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} blob:; style-src ${webview.cspSource} 'nonce-${nonce}'; ; script-src 'nonce-${nonce}';">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Packet Viewer</title>
				<style nonce="${nonce}">
				:root {
					--nettools-before: "${"\\00a0".repeat(document.sections.length.toString().length)}";
				}
				${css}
				</style>
			</head>
			<body>
				<div class="text-container">
				${lineOutput}
				</div>
				<div class="minimap-container" id="mmc">
					<canvas class="minimap" id="mm" width="5"></canvas>
				</div>
				<script nonce="${nonce}" src="${scriptUri}"></script>
			</body>
			</html>`;
	}


}

function getNonce() {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}

/**
 * Tracks all webviews.
 */
class WebviewCollection {

	private readonly _webviews = new Set<{
		readonly resource: string;
		readonly webviewPanel: vscode.WebviewPanel;
	}>();

	/**
	 * Get all known webviews for a given uri.
	 */
	public *get(uri: vscode.Uri): Iterable<vscode.WebviewPanel> {
		const key = uri.toString();
		for (const entry of this._webviews) {
			if (entry.resource === key) {
				yield entry.webviewPanel;
			}
		}
	}

	/**
	 * Add a new webview to the collection.
	 */
	public add(uri: vscode.Uri, webviewPanel: vscode.WebviewPanel) {
		const entry = { resource: uri.toString(), webviewPanel };
		this._webviews.add(entry);

		webviewPanel.onDidDispose(() => {
			this._webviews.delete(entry);
		});
	}
}

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { pcapViewerProvider } from './pcapviewer';
import { PacketDetailsProvider } from './packetdetails';
import { PacketDetailsTree } from './packetdetailstree';
import { ProtocolAnalysisTree } from './protocolanalysis';

export function activate(context: vscode.ExtensionContext) {
	
	//this is for the details pane, the "Packet Data" hex and ascii panel
	const detailsProvider = new PacketDetailsProvider(context);
	const pcapProvider = pcapViewerProvider.register(context, detailsProvider);
	const analysisProvider = new ProtocolAnalysisTree(context, [], undefined);

	vscode.commands.registerCommand('packetdetails.select', (selectionStart, selectionLength) => detailsProvider.select(selectionStart, selectionLength));

	//This is for the packet details tree view
	new PacketDetailsTree(detailsProvider, []);
	
	context.subscriptions.push(vscode.window.registerWebviewViewProvider(PacketDetailsProvider.viewType, detailsProvider));

	//this is for the main editor
	context.subscriptions.push(pcapProvider);
}

export function deactivate() {}

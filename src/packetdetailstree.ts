import * as vscode from 'vscode';
import { PacketDetailsProvider } from './packetdetails';


export class PacketDetailsTree {
	constructor(packetDetails: PacketDetailsProvider, elements: Node[]) {
    const treeDP = new NodeDependenciesProvider(elements);
		const view = vscode.window.createTreeView('packetDetails.detailstree', { treeDataProvider: treeDP, showCollapseAll: false, canSelectMany: false });
    view.onDidChangeSelection(e => {
      if (e.selection.length === 0) {
        packetDetails.select(0, 0);
      }
		});
    
    packetDetails.context.subscriptions.push(view);
	}

}

export class Node extends vscode.TreeItem {
  children: Node[] = [];
  constructor(
    public readonly label: string,
    private version?: string,
    public readonly collapsibleState?: vscode.TreeItemCollapsibleState,
    private readonly selectionStart:number = 0,
    private readonly selectionLength:number = 0
  ) {
    super(label, collapsibleState);
    //this.tooltip = `abcd`;
    this.description = this.version;
    this.command = {
      command: 'packetdetails.select',
      arguments: [selectionStart, selectionLength],
      title: 'Packet Details: Select Data'
    };
  }
  // iconPath = {
  //   light: path.join(__filename, '..', 'media', 'activitybar.svg'),
  //   dark: path.join(__filename, '..', 'media', 'activitybar.svg')
  // };
}

export class NodeDependenciesProvider implements vscode.TreeDataProvider<Node> {
  private elements:Node[];

  constructor(elements:Node[]) {
    this.elements = elements;
  }

  getTreeItem(element: Node): vscode.TreeItem {
    return element;
  }
  getChildren(element?: Node): Node[] {
    if (element) {
      return element.children;
    } else {
      return this.elements;
    }
  }
}


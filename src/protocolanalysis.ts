import * as vscode from 'vscode';
import { pcapViewerDocument } from './pcapviewer';

export class ProtocolAnalysisTree {
  
  constructor(context: vscode.ExtensionContext, elements: ProtocolNode[], document?: pcapViewerDocument) {
    const treeView = vscode.window.createTreeView('packetDetails.protocolanalysis', { treeDataProvider: new ProtocolNodeDependenciesProvider(elements), showCollapseAll: false, canSelectMany: false });
    
    treeView.onDidChangeSelection(e => {
      if (e.selection.length !== 0) {
        if (document !== undefined) {
            vscode.commands.executeCommand('packetanalysis.select', document.uri, e.selection[0]);
        }
      }
    });
    
   context.subscriptions.push(treeView);
  }


}

export class ProtocolNode extends vscode.TreeItem {
  children: ProtocolNode[] = [];
  constructor(
    public readonly label: string,
    private version?: string,
    public readonly collapsibleState?: vscode.TreeItemCollapsibleState,
    public items: number[] = []
  ) {
    super(label, collapsibleState);
    this.description = this.version;
  }
}

export class ProtocolNodeDependenciesProvider implements vscode.TreeDataProvider<ProtocolNode> {
  private elements:ProtocolNode[];

  constructor(elements:ProtocolNode[]) {
    this.elements = elements;
  }

  getTreeItem(element: ProtocolNode): vscode.TreeItem {
    return element;
  }
  getChildren(element?: ProtocolNode): ProtocolNode[] {
    if (element) {
      return element.children;
    } else {
      return this.elements;
    }
  }
}
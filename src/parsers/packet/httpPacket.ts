import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

export class HTTPPacket extends GenericPacket {
	public static readonly Name = "HTTP";

	private _lines:string[] = [];

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		const decoder = new TextDecoder('UTF-8');
		const ret = decoder.decode(this.packet);
		this._lines = ret.split(String.fromCharCode(13, 10));

		this.registerProtocol(HTTPPacket.Name, fc);
	}
	
	get isHeader():boolean {
		return this.startLine.length > 0;
	}

	get startLine():string {
		const word = this._lines[0].split(" ")[0];
		if (["HTTP/1.1", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE"].indexOf(word) > -1) {
			return this._lines[0];
		}
		return "";
	}

	get toString() {
		const header = this.startLine;
		if (header.length > 0){
			return header;
		}
		return `HTTP`;
	}

	get getProperties(): Node[] {
		let byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const element = new Node("Hypertext Transfer Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.buffer.byteLength - byteOffset);
		if (this.isHeader) {
			const startParts = this.startLine.split(" ");
			let startLine:string[] = [];
			let e2 = new Node(this.startLine, ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.startLine.length);
			if (startParts[0] === "HTTP/1.1") {
				e2.children.push(new Node(`Version`, `${startParts[0]}`, defaultState, byteOffset, startParts[0].length));
				e2.children.push(new Node(`Status`, `${startParts[1]}`, defaultState, byteOffset + startParts[0].length + 1, startParts[1].length));
				e2.children.push(new Node(`Reason`, `${startParts[2]}`, defaultState, byteOffset + startParts[0].length + startParts[1].length + 2, startParts[2].length));
			} else {
				e2.children.push(new Node(`Method`, `${startParts[0]}`, defaultState, byteOffset, startParts[0].length));
				e2.children.push(new Node(`URI`, `${startParts[1]}`, defaultState, byteOffset + startParts[0].length + 1, startParts[1].length));
				e2.children.push(new Node(`Version`, `${startParts[2]}`, defaultState, byteOffset + startParts[0].length + startParts[1].length + 2, startParts[2].length));
			}
			element.children.push(e2);

			let skipFirst = true;
			for (const line of this._lines) {
				if (!skipFirst) {
					if (line.length === 0) {
						break;
					} else {
						const split = line.split(":", 2);
						element.children.push(new Node(split[0], split[1], defaultState, byteOffset, line.length));
					}			
				} else {
					skipFirst = false;
				}
				byteOffset += line.length + 2;
			}
		}
		return [element];
	}
}


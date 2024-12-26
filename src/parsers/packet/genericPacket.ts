import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { FileContext } from "../file/FileContext";

export class GenericPacket {
	packet: DataView;

	constructor(packet: DataView, fc:FileContext) {
		this.packet = packet;
	}

	registerProtocol(Name:string, fc:FileContext) {
		let p = fc.protocols.get(Name);
		if (p === undefined) {
			p = [];
			fc.protocols.set(Name, p);
		}
		p?.push(fc.thisSection);
	}
	
	registerAddress(Name:string, fc:FileContext) {
		let p = fc.addresses.get(Name);
		if (p === undefined) {
			p = [];
			fc.addresses.set(Name, p);
		}
		p?.push(fc.thisSection);
	}

	get toString() {
		if(this.packet.byteLength === 0) {
			return "";
		}

		return `+${this.packet.byteLength} bytes unparsed data`;		
	}

	get getProperties(): Node[] {
		if(this.packet.byteLength === 0) {
			return [];
		} else {
			const elements: Node[] = [];
			let e = new Node("Unparsed Data", ``, vscode.TreeItemCollapsibleState.Collapsed);
			e.children.push(new Node("Data", `${this.toString}`));
			elements.push(e);
			return elements;
		}
	}
	
}

export interface PacketState {
	
}
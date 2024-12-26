import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { EthernetPacket } from "./ether";

export class pppoedPacket extends GenericPacket {
	public static readonly Name = "PPPoE";

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(pppoedPacket.Name, fc);

	}

	get Version():number {
		return this.packet.getUint8(0) >> 4 ;
	}
	get Type():number {
		return this.packet.getUint8(0) & 0x08;
	}
	get Code():number {
		return this.packet.getUint8(1);
	}
	get CodeName():string {
		switch (this.Code) {
			case 0x00: return "";
			case 0x09: return "Active Discovery Initiation (PADI)";
			case 0x07: return "Active Discovery Offer (PADO)";
			case 0x19: return "Active Discovery Request (PADR)";
			case 0xa7: return "Active Discovery Terminate (PADT)";
			case 0x65: return "Active Discovery Session-confirmation (PADS)";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get SessionId():number {
		return this.packet.getUint16(2);
	}
	get Length():number {
		return this.packet.getUint16(4);
	}
	
	get toString() {
		return `PPPoE ${this.CodeName}`;
	}

	get tags():pppoeTag[] {
		let i = 0;
		const ret:pppoeTag[] = [];
		while (i < this.Length) {
			ret.push(new pppoeTag(new DataView(this.packet.buffer, this.packet.byteOffset + 6 + i, this.packet.byteLength - 6 - i)));
			i += ret[ret.length-1].Length+4;
		}
		return ret;
	}

	get getProperties(): Node[] {
		const element = new Node("PPP-over-Ethernet", `${this.CodeName}`, vscode.TreeItemCollapsibleState.Collapsed);
		element.children.push(new Node(`Version`, `${this.Version}`));
		element.children.push(new Node(`Type`, `${this.Type}`));
		element.children.push(new Node(`Code`, `${this.CodeName} (0x${this.Code.toString(16).padStart(2, "0")})`));
		element.children.push(new Node(`Payload Length`, `${this.Length}`));

		if (this.tags.length) {
			const e2 = new Node("PPPoE Tags", ``, vscode.TreeItemCollapsibleState.Collapsed);
			this.tags.forEach( t => {
				e2.children.push(new Node(t.toString, ``));
			});	
			element.children.push(e2);
		}
		
		return [element];
	}
}

class pppoeTag {
	_packet: DataView;

	constructor(packet: DataView) {
		this._packet = packet;
	}
	get Type():number {
		return this._packet.getUint16(0);
	}
	get Length():number {
		let l = this._packet.getUint16(2);
		return l;
	}
	get Value() {
		switch (this.Type) {
			case 0x0000: 
				return "";
			case 0x0101:
				if (this.Length === 0) {
					return "(Any)"; 
				}
			case 0x0102: 
			case 0x0201:
			case 0x0202: 
			case 0x0203: 
				if (this.Length === 0 || this._packet.getUint8(4) === 0) {
					return "(Blank)"; 
				}
				else 
				{
					const decoder = new TextDecoder('utf-8');
					return decoder.decode(new DataView(this._packet.buffer, this._packet.byteOffset + 4, this.Length));
				}
			case 0x0103: 
			case 0x0104: 
			case 0x0105: 
			case 0x0110: 
			default: 
				let ret = "";
				for (let i = 0; i < this._packet.byteLength && i < this.Length; i++) {
					ret += this._packet.getUint8(i+4).toString(16).padStart(2, "0") + " ";
				}
				return ret.trimEnd();
		}
	}
	get TypeName():string{
		switch (this.Type) {
			case 0x0000: return "End-Of-List";
			case 0x0101: return "Service-Name";
			case 0x0102: return "AC-Name";
			case 0x0103: return "Host-Uniq";
			case 0x0104: return "AC-Cookie";
			case 0x0105: return "Vendor-Specific";
			case 0x0110: return "Relay-Session-Id";
			case 0x0201: return "Service-Name-Error";
			case 0x0202: return "AC-System-Error";
			case 0x0203: return "Generic-Error";
			default: return `Unknown type (0x${this.Type.toString(16).padStart(2, "0")})`;
		}
	}
	get toString() {
		return `${this.TypeName}: ${this.Value}`;
	}

	get getProperties(): Node[] {
		return [new Node(`${this.TypeName}`, `${this.Value}`)];
	}
}

export class pppoePacket extends GenericPacket {
	public static readonly Name = "PPPoE";

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(pppoePacket.Name, fc);
	}

	get Version():number {
		return this.packet.getUint8(0) >> 4 ;
	}
	get Type():number {
		return this.packet.getUint8(0) & 0x08;
	}
	get Code():number {
		return this.packet.getUint8(1);
	}
	get SessionId():number {
		return this.packet.getUint16(2);
	}
	get Length():number {
		return this.packet.getUint16(4);
	}
	
	get toString() {
		return `PPPoE ${super.toString}`;
	}

	get getProperties(): Node[] {
		return [];
	}
}

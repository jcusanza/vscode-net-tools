import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { EthernetPacket } from "./ether";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

export class SLL2Packet extends GenericPacket {
	public static readonly Name = "SLL2";

	private static readonly _ProtoOffset = 0;
	private static readonly _InterfaceIndexOffset = 4;
	private static readonly _ARPHRDTypeOffset = 8;
	private static readonly _PacketTypeOffset = 10;
	private static readonly _LinkLayerAddressLengthOffset = 11;
	private static readonly _LinkLayerAddressOffset = 12;

	private static readonly _ProtoLength = 2;
	private static readonly _InterfaceIndexLength = 4;
	private static readonly _ARPHRDTypeLength = 2;
	private static readonly _PacketTypeLength = 1;
	private static readonly _LinkLayerAddressLengthLength = 1;
	
	innerPacket: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		//this.registerProtocol(SLL2Packet.Name, fc);

		if (this.ARPHRDType === 1 /* Ethernet */ || this.ARPHRDType === 772 /* loopback */ ) {
			this.innerPacket = EthernetPacket.processPayload(this.proto, new DataView(packet.buffer, packet.byteOffset + 20, packet.byteLength - 20), fc);
		} else {
			this.innerPacket = new GenericPacket(new DataView(packet.buffer, packet.byteOffset + 20, packet.byteLength - 20), fc);
		}
	}
	
	get linkLayerAddress() {
		let ret = "";
		for (let i = 0; i < this.linkLayerAddressLength; i++) {
			ret += this.packet.getUint8(SLL2Packet._LinkLayerAddressOffset+i).toString(16).padStart(2, "0") + ":";
		}
		return ret.substring(0, ret.length-1);
	}

	get proto() {
		return this.packet.getUint16(SLL2Packet._ProtoOffset);
	}
	get interfaceIndex() {
		return this.packet.getUint32(SLL2Packet._InterfaceIndexOffset);
	}
	get ARPHRDType() {
		return this.packet.getUint16(SLL2Packet._ARPHRDTypeOffset);
	}
	get packetType() {
		return this.packet.getUint8(SLL2Packet._PacketTypeOffset);
	}
	get linkLayerAddressLength() {
		return this.packet.getUint8(SLL2Packet._LinkLayerAddressLengthOffset);
	}
	
	get packetTypeText() {
		switch (this.packetType) {
			case 0:
				return "Unicast to us (0)";
			case 1:
				return "Broadcast (1)";
			case 2:
				return "Multicast (2)";
			case 3:
				return "To and from someone else (3)";
			case 4:
				return "Sent by us (4)";
			default:
				return "";
		}
	}

	get toString() {
		// 00:11:22:33:44:55 > 00:11:22:33:44:55 (0x800)
		let type = "";
		switch (this.packetType) {
			case 0:
				type = `${this.linkLayerAddress} > (Us) `;  //received by us
				break;
			case 1:
				type = `${this.linkLayerAddress} > (Bc) `; //broadcast
				break;
			case 2:
				type = `${this.linkLayerAddress} > (Mc) `; //multicast
				break; 
			case 3:
				type = `${this.linkLayerAddress} > (So) `; //sent from someone else to someone else
				break;
			case 4:
				type = `${this.linkLayerAddress} > (So)`; //sent by us
				break;
			default:
				type = "";
		}
		return `${type} (0x${this.proto.toString(16).padStart(4, "0")}) ${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const elements: Node[] = [];
		let e = new Node("Linux cooked capture v2", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength - byteOffset);
		e.children.push(new Node("Protocol", `${EthernetPacket.namePayload(this.proto)} (0x${this.proto.toString(16)})`, defaultState, byteOffset + SLL2Packet._ProtoOffset, SLL2Packet._ProtoLength));
		e.children.push(new Node("Interface index", `${this.interfaceIndex}`, defaultState, byteOffset + SLL2Packet._InterfaceIndexOffset, SLL2Packet._InterfaceIndexLength));
		e.children.push(new Node("Link-layer address type", `${this.ARPHRDType}`, defaultState, byteOffset + SLL2Packet._ARPHRDTypeOffset, SLL2Packet._ARPHRDTypeLength));
		e.children.push(new Node("Packet type", `${this.packetTypeText}`, defaultState, byteOffset + SLL2Packet._PacketTypeOffset, SLL2Packet._PacketTypeLength));
		e.children.push(new Node("Link-layer address length", `${this.linkLayerAddressLength}`, defaultState, byteOffset + SLL2Packet._LinkLayerAddressLengthOffset, SLL2Packet._LinkLayerAddressLengthLength));
		e.children.push(new Node("Link-layer address", `${this.linkLayerAddress}`, defaultState, byteOffset + SLL2Packet._LinkLayerAddressOffset, this.linkLayerAddressLength));
		elements.push(e);
		return elements.concat(this.innerPacket.getProperties);
	}
}

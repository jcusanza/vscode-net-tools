import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { EthernetPacket } from "./ether";

export class vlanPacket extends GenericPacket {
	public static readonly Name = "VLAN";

	innerPacket: GenericPacket;
	private _lines:string[] = [];

	private static readonly _TCIOffset = 0;
	private static readonly _PCPOffset = 0;
	private static readonly _DEIOffset = 0;
	private static readonly _VIDOffset = 0;
	private static readonly _ProtoOffset = 2;

	private static readonly _TCILength = 2;
	private static readonly _PCPLength = 2;
	private static readonly _DEILength = 2;
	private static readonly _VIDLength = 2;
	private static readonly _ProtoLength = 2;
	private static readonly _PacketLength = 4;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(vlanPacket.Name, fc);
		fc.headers.push(this);
		this.innerPacket = EthernetPacket.processPayload(this.proto, new DataView(packet.buffer, packet.byteOffset + 4, packet.byteLength - 4), fc);
	}

	get TCI():number {
		return this.packet.getUint16(vlanPacket._TCIOffset);
	}
	get PCP():number {
		return this.TCI >> 13;
	}
	get DEI():number {
		return (this.TCI >> 12) & 0x1;
	}
	get VID():number {
		return (this.TCI & 0x0FFF);
	}

	get proto() {
		return this.packet.getUint16(vlanPacket._ProtoOffset);
	}

	get toString() {
		return `VLAN ${this.VID} (0x${this.proto.toString(16).padStart(4, "0")}) ${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		let Pri = ["Best effort (default)", "Background (lowest)", "Excellent effort", "Critical applications", "Video, <100 ms latency and jitter", "Video, <10ms latency and jitter", "Internetwork control", "Network control"];
		const elements: Node[] = [];
		let e = new Node("802.1Q Virtual LAN", `PRI: ${this.PCP}, DEI: ${this.DEI}, ID: ${this.VID}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, vlanPacket._PacketLength);
		e.children.push(new Node("PRI", `${Pri[this.PCP]} (${this.PCP})`, defaultState, byteOffset + vlanPacket._PCPOffset, vlanPacket._PCPLength));
		e.children.push(new Node("DEI", `${this.DEI === 0 ? "Ineligible" : "Eligible" }`, defaultState, byteOffset + vlanPacket._DEIOffset, vlanPacket._DEILength));
		e.children.push(new Node("ID", `${this.VID}`, defaultState, byteOffset + vlanPacket._VIDOffset, vlanPacket._VIDLength));
		e.children.push(new Node("Type", `0x${this.proto.toString(16).padStart(4, "0")}`, defaultState, byteOffset + vlanPacket._ProtoOffset, vlanPacket._ProtoLength));
		elements.push(e);
		return elements.concat(this.innerPacket.getProperties);
	}
}


import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

export class igmpPacket extends GenericPacket {
	public static readonly Name = "IGMP";

	private static readonly _TypeOffset = 0;
	private static readonly _MaxRespTimeOffset = 1;
	private static readonly _ChecksumOffset = 2;
	private static readonly _GroupAddressOffset = 4;
	private static readonly _SuppressRouterSideProcessingOffset = 8;
	private static readonly _QRVOffset = 8;
	private static readonly _QQICOffset = 9;
	private static readonly _NumberOfSourcesOffset = 10;
	private static readonly _SourcesOffset = 12;
	private static readonly _NumberOfGroupRecordsOffset = 6;
	private static readonly _GroupRecordsOffset = -1;

	private static readonly _TypeLength = 1;
	private static readonly _MaxRespTimeLength = 1;
	private static readonly _ChecksumLength = 2;
	private static readonly _GroupAddressLength = 4;
	private static readonly _SuppressRouterSideProcessingLength = 1;
	private static readonly _QRVLength = 1;
	private static readonly _QQICLength = 1;
	private static readonly _NumberOfSourcesLength = 2;
	private static readonly _SourceLength = 4;
	private static readonly _NumberOfGroupRecordsLength = 2;
	private static readonly _GroupRecordsLength = -1;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(igmpPacket.Name, fc);
	}

	get version():number {
		if (this.Type === 0x11) {
			if (this.SuppressRouterSideProcessing || this.QRV || this.QQIC || this.NumberOfSources) {
				return 3;
			} else {
				return 1;
			}
		} else if (this.Type === 0x12) {
			return 1;
		} else if (this.Type === 0x22) {
			return 3;
		} else {
			return 2;
		}
	}
	get Type():number {
		return this.packet.getUint8(igmpPacket._TypeOffset);
	}
	get MaxRespTime():number {  
		let val = this.packet.getUint8(igmpPacket._MaxRespTimeOffset);
		if (val < 128) {
			return val;
		}
		let mant = val & 0x0F;
		let exp = (val >> 4) & 0x07;
		
		return (mant | 0x10) << (exp + 3);
	}
	get Checksum():number {
		return this.packet.getUint16(igmpPacket._ChecksumOffset);
	}

	get GroupAddress():string {
		let ret = "";
		ret += this.packet.getUint8(igmpPacket._GroupAddressOffset) + ".";
		ret += this.packet.getUint8(igmpPacket._GroupAddressOffset+1) + ".";
		ret += this.packet.getUint8(igmpPacket._GroupAddressOffset+2) + ".";
		ret += this.packet.getUint8(igmpPacket._GroupAddressOffset+3);
		return ret;
	}

	get SuppressRouterSideProcessing():boolean {
		if (this.Type !== 0x11 || this.packet.byteLength < 9) {
			return false;
		}
		return ((this.packet.getUint8(igmpPacket._SuppressRouterSideProcessingOffset) >> 3) & 0x01) > 0;
	}
	get QRV():number {
		if (this.Type !== 0x11 || this.packet.byteLength < 9) {
			return 0;
		}
		return this.packet.getUint8(igmpPacket._QRVOffset) & 0x07;
	}
	get QQIC():number {
		if (this.Type !== 0x11 || this.packet.byteLength < 10) {
			return 0;
		}
		let val = this.packet.getUint8(igmpPacket._QQICOffset);
		if (val < 128) {
			return val;
		}
		let mant = val & 0x0F;
		let exp = (val >> 4) & 0x07;
		
		return (mant | 0x10) << (exp + 3);
	}
	get NumberOfSources():number {
		if (this.Type !== 0x11 || this.packet.byteLength < 12) {
			return 0;
		}
		return this.packet.getUint16(igmpPacket._NumberOfSourcesOffset); 
	}
	
	get SourcesLength():number {
		return this.NumberOfSources * 4;
	}

	get Sources():String[] {
		const ret:String[] = [];
		for (let i = 0; i < this.NumberOfSources; i++) {
			let source = "";
			source += this.packet.getUint8(igmpPacket._SourcesOffset + 0 + i*4) + ".";
			source += this.packet.getUint8(igmpPacket._SourcesOffset + 1 + i*4) + ".";
			source += this.packet.getUint8(igmpPacket._SourcesOffset + 2 + i*4) + ".";
			source += this.packet.getUint8(igmpPacket._SourcesOffset + 3 + i*4);
			ret.push(source);
		}; 
		return ret;
	}

	get NumberOfGroupRecords():number {
		if (this.Type !== 0x22) {
			return 0;
		}
		return this.packet.getUint16(igmpPacket._NumberOfGroupRecordsOffset); 
	}

	get GroupRecords():GroupRecord[] {
		const ret:GroupRecord[] = [];
		let nextOffset = this.packet.byteOffset + 8;
		for (let i = 0; i < this.NumberOfGroupRecords && nextOffset < this.packet.buffer.byteLength; i++) {
			let nextLen = 8 + this.packet.getUint8(nextOffset-this.packet.byteOffset+1)*4 + this.packet.getUint16(nextOffset-this.packet.byteOffset+2)*4;			
			let gr = new GroupRecord(new DataView(this.packet.buffer, nextOffset, nextOffset + nextLen < this.packet.buffer.byteLength ? nextLen : this.packet.buffer.byteLength - nextOffset));
			nextOffset += nextLen; 
			ret.push(gr);
		}; 
		return ret;
	}

	get TypeName():string {
		switch (this.Type) {
			case 0x11: return "Membership Query";
			case 0x12: return "Membership Report";
			case 0x16: return "Membership Report";
			case 0x17: return "Leave Group";
			case 0x22: return "Membership Report";
			case 0xFF: return "Hello";
			case 0xFE: return "Bye";
			case 0xFD: return "Join a group";
			case 0xFC: return "Leave a group";
			default: return `Invalid Type 0x${this.Type.toString(16).padStart(2, "0")}`;
		}
	}

	get toString() {
		if (this.Type === 0xFF || this.Type === 0xFE || this.Type === 0xFD || this.Type === 0xFC) {
			return `RGMP ${this.TypeName}`;
		} else {
			if (this.Type === 0x22) {
				let ret = `IGMPv${this.version} ${this.TypeName}`;
				for (const gr of this.GroupRecords) {
					ret += ` / ${gr.toString}`;
				}
				return ret;
			} else if (this.Type === 0x11) {
					if (this.GroupAddress === "0.0.0.0") {
						return `IGMPv${this.version} ${this.TypeName}, general`;
					} else {
						return `IGMPv${this.version} ${this.TypeName} for ${this.GroupAddress}`;
					}
			} else if (this.Type === 0x16) {
				return `IGMPv${this.version} ${this.TypeName} group ${this.GroupAddress}`;
			} else {
				return `IGMPv${this.version} ${this.TypeName}`;
			}
		}
		
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		let igmpName = "";
		
		if (this.Type === 0xFF || this.Type === 0xFE || this.Type === 0xFD || this.Type === 0xFC) {
			igmpName = `Router-port Group Management Protocol`; 
		} else {
			igmpName = `Internet Group Management Protocol`; 
		}
		
		const element = new Node(igmpName, ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node(`Type`, `${this.TypeName} (0x${this.Type.toString(16).padStart(2, "0")})`, defaultState, byteOffset + igmpPacket._TypeOffset, igmpPacket._TypeLength));

		if (this.Type === 0x11) {
			element.children.push(new Node(`Max Resp Time`, `${this.MaxRespTime/10.0} sec (0x${this.MaxRespTime.toString(16).padStart(2, "0")})`, defaultState, byteOffset + igmpPacket._MaxRespTimeOffset, igmpPacket._MaxRespTimeLength));
		}	
		element.children.push(new Node(`Checksum`, `0x${this.Checksum.toString(16).padStart(4, "0")}`, defaultState, byteOffset + igmpPacket._ChecksumOffset, igmpPacket._ChecksumLength));
		if (this.Type !== 0x22) {
			element.children.push(new Node(`Multicast Address`, `${this.GroupAddress}`, defaultState, byteOffset + igmpPacket._GroupAddressOffset, igmpPacket._GroupAddressLength)); 
		} else {
			element.children.push(new Node(`Number of Group Records`, `${this.NumberOfGroupRecords}`, defaultState, byteOffset + igmpPacket._NumberOfGroupRecordsOffset, igmpPacket._NumberOfGroupRecordsLength)); 
			for (const gr of this.GroupRecords) {
				element.children = element.children.concat(gr.getProperties);
			}
		}
		if (this.version === 3 && this.Type === 0x11) {
			element.children.push(new Node(`Suppress Router Side Processing`, `${this.SuppressRouterSideProcessing}`, defaultState, byteOffset + igmpPacket._SuppressRouterSideProcessingOffset, igmpPacket._SuppressRouterSideProcessingLength)); 
			element.children.push(new Node(`Querier's Robustness Value (QRV)`, `${this.QRV}`, defaultState, byteOffset + igmpPacket._QRVOffset, igmpPacket._QRVLength)); 
			element.children.push(new Node(`Querier's Query Interval (QQIC)`, `${this.QQIC} sec`, defaultState, byteOffset + igmpPacket._QQICOffset, igmpPacket._QQICLength)); 

			if (this.Sources.length) {
				let sourceOffset = byteOffset + igmpPacket._SourcesOffset;
				const element2 = new Node(`Sources`, `${this.NumberOfSources}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + igmpPacket._NumberOfSourcesOffset, igmpPacket._NumberOfSourcesLength);
				for (const s of this.Sources) {
					element2.children.push(new Node(`Source Address`,  `${s}`, defaultState, sourceOffset, igmpPacket._SourceLength));
					sourceOffset += igmpPacket._SourceLength;
				}
				element.children.push(element2);
			}	
		}

		return [element];
	}
}

class GroupRecord {
	private static readonly _RecordTypeOffset = 0;
	private static readonly _NumberOfSourcesOffset = 2;
	private static readonly _MulticastAddressOffset = 4;
	private static readonly _SourceAddressesOffset = 8;

	private static readonly _RecordTypeLength = 1;
	private static readonly _NumberOfSourcesLength = 2;
	private static readonly _MulticastAddressLength = 4;
	private static readonly _SourceAddressLength = 4;

	constructor(private _record: DataView) {
	}

	get RecordType():number {
		return this._record.getUint8(GroupRecord._RecordTypeOffset);
	}
	get NumberOfSources():number {
		return this._record.getUint16(GroupRecord._NumberOfSourcesOffset);
	}
	get MulticastAddress():string {
		let ret:string = "";
		ret += this._record.getUint8(GroupRecord._MulticastAddressOffset) + ".";
		ret += this._record.getUint8(GroupRecord._MulticastAddressOffset+1) + ".";
		ret += this._record.getUint8(GroupRecord._MulticastAddressOffset+2) + ".";
		ret += this._record.getUint8(GroupRecord._MulticastAddressOffset+3);
		return ret;
	}
	get SourceAddresses():string[] {
		const ret:string[] = [];
		for (let i = 0; i < this.NumberOfSources; i++) {
			let source = "";
			source += this._record.getUint8(GroupRecord._SourceAddressesOffset + 0 + i*4) + ".";
			source += this._record.getUint8(GroupRecord._SourceAddressesOffset + 1 + i*4) + ".";
			source += this._record.getUint8(GroupRecord._SourceAddressesOffset + 2 + i*4) + ".";
			source += this._record.getUint8(GroupRecord._SourceAddressesOffset + 3 + i*4);
			ret.push(source);
		}; 
		return ret;
	}
	get toString() {
		let action = "";
		switch (this.RecordType) {
			case 1:
			case 2:
			case 4:
				action = "Join group";
				break;
			default: //5
				action = "Group";
		}
		let ret = `${action} ${this.MulticastAddress}, `;
		if (this.NumberOfSources === 0) {
			return ret + `any sources`;
		}
		ret += `new source {`;
		for (const s of this.SourceAddresses) {
			ret += `${s}, `;
		}
		return ret.substring(0, ret.length - 2) + "}";
	}

	get getProperties(): Node[] {
		const byteOffset = this._record.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const RecordTypes = ["", "Mode is Include", "Mode is Exclude", "Change to Include mode", "Change to Exclude mode", "Allow new sources", "Block old sources"];
		const element = new Node(`Group Record`, `${this.MulticastAddress}, ${RecordTypes[this.RecordType]}`, vscode.TreeItemCollapsibleState.Collapsed, this._record.byteOffset, GroupRecord._SourceAddressesOffset + this.NumberOfSources*4);
		element.children.push(new Node(`Record Type`, `${RecordTypes[this.RecordType]} (${this.RecordType})`, defaultState, byteOffset + GroupRecord._RecordTypeOffset, GroupRecord._RecordTypeLength));
		element.children.push(new Node(`Multicast Address`, `${this.MulticastAddress}`, defaultState, byteOffset + GroupRecord._MulticastAddressOffset, GroupRecord._MulticastAddressLength));

		if (this.SourceAddresses.length) {
			let sourceOffset = byteOffset + GroupRecord._SourceAddressesOffset;
			const element2 = new Node(`Sources`, `${this.NumberOfSources}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + GroupRecord._NumberOfSourcesOffset, GroupRecord._NumberOfSourcesLength);
			for (const s of this.SourceAddresses) {
				element2.children.push(new Node(`Source Address`,  `${s}`, defaultState, sourceOffset, GroupRecord._SourceAddressLength));
				sourceOffset += GroupRecord._SourceAddressLength;
			}
			element.children.push(element2);
		}

		return [element];
	}
}
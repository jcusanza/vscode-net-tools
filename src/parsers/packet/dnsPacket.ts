import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { Address6 } from "ip-address";

export class DNSPacket extends GenericPacket {
	public static readonly Name = "DNS";

	private static readonly _TransactionIDOffset = 0;
	private static readonly _ResponseOffset = 2;
	private static readonly _OpcodeOffset = 2;
	private static readonly _AuthoritativeOffset = 2;
	private static readonly _TruncatedOffset = 2;
	private static readonly _RecursionDesiredOffset = 2;
	private static readonly _RecursionAvailableOffset = 3;
	private static readonly _ZOffset = 3;
	private static readonly _ReplyCodeOffset = 3;
	private static readonly _QuestionsOffset = 4;
	private static readonly _AnswerRRsOffset = 6;
	private static readonly _AuthorityRRsOffset = 8;
	private static readonly _AdditionalRRsOffset = 10;
	private static readonly _RecordOffset = 12;

	private static readonly _TransactionIDLength = 2;
	private static readonly _ResponseLength = 1;
	private static readonly _OpcodeLength = 1;
	private static readonly _AuthoritativeLength = 1;
	private static readonly _TruncatedLength = 1;
	private static readonly _RecursionDesiredLength = 1;
	private static readonly _RecursionAvailableLength = 1;
	private static readonly _ZLength = 1;
	private static readonly _ReplyCodeLength = 1;
	private static readonly _QuestionsLength = 2;
	private static readonly _AnswerRRsLength = 2;
	private static readonly _AuthorityRRsLength = 2;
	private static readonly _AdditionalRRsLength = 2;

	packet: DataView;
	question: BaseRecord[] = [];
	answer: ResourceRecord[] = [];
	authority: ResourceRecord[] = [];
	additional: ResourceRecord[] = [];
	truncated: boolean;	

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;
		let recordOffset = DNSPacket._RecordOffset;

		this.registerProtocol(DNSPacket.Name, fc);

		try {
			for(let i  = 0; i < this.qdCount; i++) {
				this.question.push(new BaseRecord(packet, recordOffset));
				recordOffset += this.question[i].length;
			}
			for(let i  = 0; i < this.anCount; i++) {
				this.answer.push(new ResourceRecord(packet, recordOffset));
				recordOffset += this.answer[i].length;
			}
			for(let i  = 0; i < this.nsCount; i++) {
				this.authority.push(new ResourceRecord(packet, recordOffset));
				recordOffset += this.authority[i].length;
			}		
			for(let i  = 0; i < this.arCount; i++) {
				this.additional.push(new ResourceRecord(packet, recordOffset));
				recordOffset += this.additional[i].length;
			}
		} catch 
		{
			this.truncated = true; 
			return;
		}
		this.truncated = false;
	}

	get TransactionID() {
		return this.packet.getUint16(DNSPacket._TransactionIDOffset);
	}

    get Response():boolean {
		return (this.packet.getUint8(DNSPacket._ResponseOffset) & 0x80) === 0x80;
	}

    get Opcode() {
		return (this.packet.getUint8(DNSPacket._OpcodeOffset) & 0x78) >> 3;
	}

    get opMessage() {
        switch(this.Opcode) {
            case 0: return "Standard query";
            case 1: return "Inverse query";
            case 2: return "Server status request";
            default: return "Unknown query type";
        }
    }

    get Authoritative() {
		return (this.packet.getUint8(DNSPacket._AuthoritativeOffset) & 0x4) >> 2;
	}	

    get Truncated() {
		return (this.packet.getUint8(DNSPacket._TruncatedOffset) & 0x2) >> 1;
	}	

    get RecursionDesired() {
		return this.packet.getUint8(DNSPacket._RecursionDesiredOffset) & 0x1;
	}	

    get RecursionAvailable() {
		return this.packet.getUint8(DNSPacket._RecursionAvailableOffset) >> 7;
	}	
    
    get Z() {
		return (this.packet.getUint8(DNSPacket._ZOffset) & 0x70) >> 4;
	}	

    get ReplyCode() {
		return this.packet.getUint8(DNSPacket._ReplyCodeOffset) & 0x0f;
	}	

    get qdCount() {
		return this.packet.getUint16(DNSPacket._QuestionsOffset);
	}	

    get anCount() {
		return this.packet.getUint16(DNSPacket._AnswerRRsOffset);
	}	

    get nsCount() {
		return this.packet.getUint16(DNSPacket._AuthorityRRsOffset);
	}   	

    get arCount() {
		return this.packet.getUint16(DNSPacket._AdditionalRRsOffset);
	}	

	get toString() {
		try {
			let questions = "";
			this.question.forEach(item => {
				questions += item.name + " ";
			});
			questions = questions.trimEnd();

			let answers = "";
			this.answer.forEach(item => {
				answers += item.name + " ";
			});
			answers = answers.trimEnd();
			let strTrunc = "";
			if (this.truncated) {
				strTrunc = " [Truncated]";
			}
			return `DNS ${this.opMessage}${this.Response ? " response" : ""} 0x${this.TransactionID.toString(16).padStart(4, `0`)}${this.qdCount ? ", " + questions : ""}${this.anCount ? ", " + answers : ""}${strTrunc}`;
		} catch {
			return `DNS - parse error`;
		}
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const element = new Node("Domain Name System", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
        element.children.push(new Node("Transaction ID", `${this.TransactionID}`, defaultState, byteOffset + DNSPacket._TransactionIDOffset, DNSPacket._TransactionIDLength));
		const element2 = new Node("Flags", `0x${this.Opcode.toString(16).padStart(4, "0")} ${this.opMessage}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + DNSPacket._OpcodeOffset, DNSPacket._OpcodeLength);
		element2.children.push(new Node(`Response`, `${this.Response ? `Message is a response` : `Message is a query`}`, defaultState, byteOffset + DNSPacket._ResponseOffset, DNSPacket._ResponseLength));
		element2.children.push(new Node(`Authoritative`, `Server is ${this.Authoritative ? `` : `not `}an authority for domain`, defaultState, byteOffset + DNSPacket._AuthoritativeOffset, DNSPacket._AuthoritativeLength));
		element2.children.push(new Node(`Truncated`, `Message is ${this.Truncated ? `` : `not `}truncated`, defaultState, byteOffset + DNSPacket._TruncatedOffset, DNSPacket._TruncatedLength));
		element2.children.push(new Node(`Recursion desired`, `Do ${this.RecursionDesired ? `` : `not `}query recursively`, defaultState, byteOffset + DNSPacket._RecursionDesiredOffset, DNSPacket._RecursionDesiredLength));
		element2.children.push(new Node(`Recursion available`, `Server can${this.RecursionAvailable ? `` : `not`} do recursive queries`, defaultState, byteOffset + DNSPacket._RecursionAvailableOffset, DNSPacket._RecursionAvailableLength));
		element2.children.push(new Node(`Z`, `Reserved (${this.Z})`, defaultState, byteOffset + DNSPacket._ZOffset, DNSPacket._ZLength));
		element.children.push(element2);
        element.children.push(new Node("Questions", `${this.qdCount}`, defaultState, byteOffset + DNSPacket._QuestionsOffset, DNSPacket._QuestionsLength));
        element.children.push(new Node("Answer RRs", `${this.anCount}`, defaultState, byteOffset + DNSPacket._AnswerRRsOffset, DNSPacket._AnswerRRsLength));
        element.children.push(new Node("Authority RRs", `${this.nsCount}`, defaultState, byteOffset + DNSPacket._AuthorityRRsOffset, DNSPacket._AuthorityRRsLength));
        element.children.push(new Node("Additional RRs", `${this.arCount}`, defaultState, byteOffset + DNSPacket._AdditionalRRsOffset, DNSPacket._AdditionalRRsLength));

		let _byteOffset = byteOffset + DNSPacket._RecordOffset;
		let _len = 0;

		if(this.qdCount) {
			this.question.forEach(item => {
				_len += item.length;
			});

			const e2 = new Node("Queries", ``, vscode.TreeItemCollapsibleState.Collapsed, _byteOffset, _len);
			this.question.forEach(item => {
				e2.children.push(new Node(item.toString, ``, defaultState, _byteOffset, item.length));
				_byteOffset += item.length;
			});
		    element.children.push(e2);
		}

		if(this.anCount) {
			_len = 0;
			this.answer.forEach(item => {
				_len += item.length;
			});

			const e2 = new Node("Answers", ``, vscode.TreeItemCollapsibleState.Collapsed, _byteOffset, _len);
			this.answer.forEach(item => {
				e2.children = e2.children.concat(item.getProperties);
			});
		    element.children.push(e2);
		}
		
		if(this.nsCount) {
			_len = 0;
			this.authority.forEach(item => {
				_len += item.length;
			});

			const e2 = new Node("Authoritative nameservers", ``, vscode.TreeItemCollapsibleState.Collapsed, _byteOffset, _len);
			this.authority.forEach(item => {
				e2.children = e2.children.concat(item.getProperties);
			});
		    element.children.push(e2);
		}
		
		if(this.arCount) {
			_len = 0;
			this.additional.forEach(item => {
				_len += item.length;
			});

			const e2 = new Node("Additional", ``, vscode.TreeItemCollapsibleState.Collapsed, _byteOffset, _len);
			this.additional.forEach(item => {
				e2.children = e2.children.concat(item.getProperties);
			});
		    element.children.push(e2);
		}

		if (this.truncated) {
			element.children.push(new Node("[Truncated]", ``));
		}
        return [element];
	}
}

class BaseRecord {
	packet: DataView;
	name: string = "";
	nameLength: number;
	_offset: number;

		
	static GetLabel(offset:number, record:DataView):[string, number] {
		let count = record.getUint8(offset);
		if (count === 0) {
			return ["", 1];
		}

		if ((count & 0xC0) === 0xC0) {
			const offsetLookup = record.getUint16(offset) & 0x3FFF;  //0011 1111
			const [label, retoffset] = BaseRecord.GetLabel(offsetLookup, record);
			return [label, 2];
		} else {
			const decoder = new TextDecoder('utf-8');
			const thisName = decoder.decode(new DataView(record.buffer, record.byteOffset + offset + 1, count));
			const [theRest, restLen]  = BaseRecord.GetLabel(offset + 1 + count, record);

			if (restLen === 1) {
				return [thisName, count+restLen+1];
			} else {
				return [thisName + "." + theRest, count+restLen+1];
			}
		}
	}

	constructor(packet: DataView, recordOffset: number) {
		this.packet = packet;
		this._offset = recordOffset;
		[this.name, this.nameLength] = BaseRecord.GetLabel(recordOffset, packet);
	}

	get getName() {
		return this.name;
	}

	get type() {
		return this.packet.getUint16(this._offset + this.nameLength);
	}
	get typeName() {
		switch (this.type) {
			case 1: return "A";
			case 2: return "NS";
			case 3: return "MD";
			case 4: return "MF";
			case 5: return "CNAME";
			case 6: return "SOA";
			case 7: return "MB";
			case 8: return "MG";
			case 9: return "MR";
			case 10: return "NULL";
			case 11: return "WKS";
			case 12: return "PTR";
			case 13: return "HINFO";
			case 14: return "MINFO";
			case 15: return "MX";
			case 16: return "TXT";
			case 18: return "AFSDB";
			case 28: return "AAAA";
			case 33: return "SRV";
			case 47: return "NSEC";
			case 252: return "AXFR";
			case 253: return "MAILB";
			case 254: return "MAILA";
			case 255: return "*";
			default: return "Unknown";
		}
	}

	get class() {
		return this.packet.getUint16(this._offset + this.nameLength + 2);
	}
	get className():string {
		switch (this.class) {
			case 1: return "IN";
			case 2: return "CS";
			case 3: return "CH";
			case 4: return "HS";
			case 255: return "*";
			default: return "";
		}
	}


	get length() {
		return this.nameLength + 4;
	}

	get toString() {
		return `${this.name}: type ${this.typeName} (${this.type}), class ${this.className} (${this.class})`;
	}
}

class ResourceRecord extends BaseRecord {

	constructor(packet: DataView, recordOffset: number) {
		super(packet, recordOffset);
	}

	get ttl() {
		return this.packet.getUint32(this._offset + this.nameLength + 4);
	}

	get rdLength() {
		return this.packet.getUint16(this._offset + this.nameLength + 8);
	}	

	get length() {
		return this.nameLength + 10 + this.rdLength;
	}

	get rdata():RDATABase {
		const newOffset = this._offset + this.nameLength + 10;
		switch (this.type) {
			case 1: //A
				return new ARData(this.packet, newOffset, this.rdLength);
			case 5: //CNAME
				return new CNAMEData(this.packet, newOffset, this.rdLength);
			case 6: //SOA
				return new SOAData(this.packet, newOffset, this.rdLength);
			case 12: //PTR
				return new PTRRData(this.packet, newOffset, this.rdLength);
			case 16: //TXT
				return new TXTRData(this.packet, newOffset, this.rdLength);
			case 28: //AAAA
				return new AAAAData(this.packet, newOffset, this.rdLength);
			case 33: //SRV
				return new SRVRData(this.packet, newOffset, this.rdLength);
			default:
				return new RDATABase(this.packet, newOffset, this.rdLength);
		}
	}
	
	get toString() {
		return `${this.name}: type ${this.typeName}, class ${this.className}, time to live: ${this.ttl} seconds, data length${this.rdLength}, ${this.rdata}`;
	}

	get getProperties(): Node[] {
		const element = new Node(`${this.name}`, `Type ${this.typeName}, Class ${this.className}`, vscode.TreeItemCollapsibleState.Collapsed, this.packet.byteOffset + this._offset, this.nameLength);
		element.children.push(new Node("Time to live", `${this.ttl} sec`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset + this._offset + this.nameLength + 4, 4));
		element.children.push(new Node("Data length", `${this.rdLength}`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset + this._offset + this.nameLength + 8, 2));
		element.children = element.children.concat(this.rdata.getProperties);
		return [element];
	}
}

class RDATABase { 
	_rdata: DataView;
	_offset: number;
	_length: number;

	constructor(rdata:DataView, offset:number, length:number) {
		this._rdata = rdata;
		this._offset = offset;
		this._length = length;
	}

	get toString():string {
		let ret = "";
		return ret;
	}

	get getProperties(): Node[] {
		return [];
	}
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   TXT-DATA                    /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
class TXTRData extends RDATABase {
	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
	}
	get txt():string[]
	{
		const decoder = new TextDecoder('utf-8');
		const ret:string[] = [];
		let len = 0;
		for (let i = this._offset; i < this._offset + this._length; i+=len+1) {
			len = this._rdata.getUint8(i);
			ret.push(decoder.decode(new DataView(this._rdata.buffer, this._rdata.byteOffset + i + 1, len)));
		}
		return ret;
	}

	get getProperties(): Node[] {
		const elements: Node[] = [];
		let offset = this._rdata.byteOffset + this._offset;

		this.txt.forEach(a => {
			elements.push(new Node(`TXT`, `${a}`, vscode.TreeItemCollapsibleState.None, offset, a.length+1));
			offset += a.length+1;
		});
		return elements;
	}
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   PTRDNAME                    /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
class PTRRData extends RDATABase {
	length: number;
	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
		this.length = length;
	}
	get ptrdname():string
	{
		const [name, len] = BaseRecord.GetLabel(this._offset + 0, this._rdata);
		return name;
	}

	get getProperties(): Node[] {
		return [new Node(`Domain Name`, `${this.ptrdname}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset, this.length)];
	}
}

class SRVRData extends RDATABase {
	target:string;
	targetlength:number;

	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
		const [name, len] = BaseRecord.GetLabel(this._offset + 6, this._rdata);
		this.target = name;
		this.targetlength = len;
	}
	get priority():number
	{
		return this._rdata.getUint16(this._offset + 0);
	}
	get weight():number
	{
		return this._rdata.getUint16(this._offset + 2);
	}
	get port():number
	{
		return this._rdata.getUint16(this._offset + 4);
	}

	get getProperties(): Node[] {
		return [
			new Node(`Priority`, `${this.priority}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + 0, 2),
			new Node(`Weight`, `${this.weight}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + 2, 2),
			new Node(`Port`, `${this.port}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + 4, 2),
			new Node(`Target`, `${this.target}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + 6, this.targetlength)
		];
	}
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   PTRDNAME                    /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
class ARData extends RDATABase {
	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
	}
	get address():string
	{
		return `${this._rdata.getUint8(this._offset + 0)}.${this._rdata.getUint8(this._offset + 1)}.${this._rdata.getUint8(this._offset + 2)}.${this._rdata.getUint8(this._offset + 3)}`;
	}

	get getProperties(): Node[] {
		return [
			new Node(`Address`, `${this.address}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset, 4)
		];
	}
}

class AAAAData extends RDATABase {
	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
	}
	get address():string
	{
		const a = this._rdata.buffer.slice(this._offset, this._offset + 16);
		const ua = new Uint8Array(a);
		const na = Array.from(ua);
		return Address6.fromByteArray(na).correctForm();
	}

	get getProperties(): Node[] {
		return [
			new Node(`Address`, `${this.address}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset, 16)
		];
	}
}

class CNAMEData extends RDATABase {
	length: number;

	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
		this.length = length;
	}
	get cname():string
	{
		const [name, len] = BaseRecord.GetLabel(this._offset + 0, this._rdata);
		return name;
	}

	get getProperties(): Node[] {
		return [
			new Node(`CNAME`, `${this.cname}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset, this.length)
		];
	}
}

class SOAData extends RDATABase {
	_mname: string;
	_rname: string;
	_mlen: number;
	_rlen: number;

	constructor(rdata:DataView, offset:number, length:number) {
		super(rdata, offset, length);
		[this._mname, this._mlen] = BaseRecord.GetLabel(this._offset + 0, this._rdata);
		[this._rname, this._rlen] = BaseRecord.GetLabel(this._offset + this._mlen, this._rdata);
	}
	get mname():string
	{
		return this._mname;
	}
	get rname():string
	{
		return this._rname;
	}
	get serial():number
	{
		return this._rdata.getUint32(this._offset + this._mlen + this._rlen);
	}
	get refresh():number
	{
		return this._rdata.getUint32(this._offset + this._mlen + this._rlen + 4);
	}	
	get retry():number
	{
		return this._rdata.getUint32(this._offset + this._mlen + this._rlen + 8);
	}	
	get expire():number
	{
		return this._rdata.getUint32(this._offset + this._mlen + this._rlen + 12);
	}	
	get minimum():number
	{
		return this._rdata.getUint32(this._offset + this._mlen + this._rlen + 16);
	}

	get getProperties(): Node[] {
		return [
			new Node(`Primary name server`, `${this.mname}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset, this._mlen),
			new Node(`Responsible authority's mailbox`, `${this.rname}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen, this._rlen),
			new Node(`Serial Number`, `${this.serial}`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen + this._rlen + 0, 4),
			new Node(`Refresh Interval`, `${this.refresh} sec`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen + this._rlen + 4, 4),
			new Node(`Retry Interval`, `${this.retry} sec`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen + this._rlen + 8, 4),
			new Node(`Expire limit`, `${this.expire} sec`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen + this._rlen + 12, 4),
			new Node(`Minimum TTL`, `${this.minimum} sec`, vscode.TreeItemCollapsibleState.None, this._rdata.byteOffset + this._offset + this._mlen + this._rlen + 16, 4)
		];
	}
}
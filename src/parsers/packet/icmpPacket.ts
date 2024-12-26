import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

export class ICMPPacket extends GenericPacket {
    public static readonly Name = "ICMP";
    packet: DataView;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	    this.packet = packet;
        this.registerProtocol(ICMPPacket.Name, fc);

    }

    get message(): ICMPMessage {
        return ICMPMessage.create(this.packet);
    }

    get toString() {
        return `ICMP ${this.message.toString}`;
    }

    get getProperties() {
        return this.message.getProperties;
    }
}

class ICMPMessage {
	protected static readonly _TypeOffset = 0;
	protected static readonly _CodeOffset = 1;
	protected static readonly _ChecksumOffset = 2;
	protected static readonly _MessageOffset = 4;

	protected static readonly _TypeLength = 1;
	protected static readonly _CodeLength = 1;
	protected static readonly _ChecksumLength = 2;
    
    packet: DataView;

    constructor(dv: DataView) {
        this.packet = dv;
    }

    getOriginalData() {
        let ret = "";
        for (let i = 8; i < this.packet.byteLength; i++) {
            ret += this.packet.getUint8(i).toString(16).padStart(2, "0");
        }
        return ret;
    }

    static create(dv: DataView): ICMPMessage {
	
		switch (dv.getUint8(ICMPMessage._TypeOffset)) {
			case 0: 
				return new ICMPEchoReply(dv);
			case 3:  
				return new ICMPDestinationUnreachable(dv);
			case 4: 
				return new ICMPSourceQuench(dv);
			case 5: 
				return new ICMPRedirect(dv);
			case 8: 
				return new ICMPEchoRequest(dv);
			case 11: 
				return new ICMPTimeExceeded(dv);
			case 12: 
				return new ICMPParameterProblem(dv);
			case 13:
				return new ICMPTimestamp(dv);
			case 14: 
				return new ICMPTimestampReply(dv);
			case 15: 
				return new ICMPInformationRequest(dv);
			case 16: 
				return new ICMPInformationReply(dv);
			default:
				return new ICMPMessage(dv); 
		}
	}


    get type() {
        return this.packet.getUint8(ICMPMessage._TypeOffset);
    }

    get code() {
        return this.packet.getUint8(ICMPMessage._CodeOffset);
    }

    get checksum() {
        return this.packet.getUint16(ICMPMessage._ChecksumOffset);
    }

    get toString() {
        return `Unknown ICMP Type: ${this.type}, Code: ${this.code}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Unknown (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		return [element];
	}
}

class ICMPDestinationUnreachable extends ICMPMessage {
    get codeMessage() {
        switch (this.code) {
            case 0: return "Net unreachable";
            case 1: return "Host unreachable";
            case 2: return "Protocol unreachable";
            case 3: return "Port unreachable";
            case 4: return "Fragmentation needed and DF set";
            case 5: return "Source route failed";
            default: return "Unknown code";
        }
    }

    get originalData() {
        return this.getOriginalData();
    }

    get toString() {
        return `Destination Unreachable: ${this.codeMessage}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Destination Unreachable (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.codeMessage} (${this.code})`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Original Data", `${this.originalData}`, defaultState, byteOffset + ICMPMessage._MessageOffset, this.packet.byteLength - ICMPMessage._MessageOffset));
		return [element];
	}
}

class ICMPSourceQuench extends ICMPMessage {
    get originalData() {
        return this.getOriginalData();
    }

    get toString() {
        return "Source Quench";
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Source Quench`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Original Data", `${this.originalData}`, defaultState, byteOffset + ICMPMessage._MessageOffset, this.packet.byteLength - ICMPMessage._MessageOffset));
		return [element];
	}
}

class ICMPRedirect extends ICMPMessage {
    get originalData() {
        return this.getOriginalData();
    }

    get toString() {
        return `Redirect`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Redirect`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Original Data", `${this.originalData}`, defaultState, byteOffset + ICMPMessage._MessageOffset, this.packet.byteLength - ICMPMessage._MessageOffset));
		return [element];
	}
}

class ICMPTimeExceeded extends ICMPMessage {
    get codeMessage() {
        switch (this.code) {
            case 0: return "TTL expired in transit";
            case 1: return "Fragment reassembly time exceeded";
            default: return "Unknown code";
        }
    }

    get originalData() {
        return this.getOriginalData();
    }

    get toString() {
        return `Time Exceeded: ${this.codeMessage}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Time Exceeded (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Original Data", `${this.originalData}`, defaultState, byteOffset + ICMPMessage._MessageOffset, this.packet.byteLength - ICMPMessage._MessageOffset));
		return [element];
	}
}

class ICMPParameterProblem extends ICMPMessage {
	protected static readonly _PointerOffset = 4;
	protected static readonly _PointerLength = 4;
    
    get pointer() {
        return this.packet.getUint32(ICMPParameterProblem._PointerOffset);
    }

    get codeMessage() {
        switch (this.code) {
            case 0: return "Pointer indicates error";
            case 1: return "Missing required option";
            case 2: return "Bad length";
            default: return "Unknown code";
        }
    }

    get originalData() {
        return this.getOriginalData();
    }

    get toString() {
        return `Parameter Problem: ${this.codeMessage}, Pointer: ${this.pointer}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Parameter Problem (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Pointer", `${this.pointer}`, defaultState, byteOffset + ICMPParameterProblem._PointerOffset, ICMPParameterProblem._PointerLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Original Data", `${this.originalData}`, defaultState, byteOffset + ICMPMessage._MessageOffset, this.packet.byteLength - ICMPMessage._MessageOffset));
		return [element];
	}
}


class ICMPEchoRequest extends ICMPMessage {
	protected static readonly _IdentifierOffset = 4;
	protected static readonly _SequenceNumOffset = 6;
	protected static readonly _DataOffset = 8;

    protected static readonly _IdentifierLength = 2;
	protected static readonly _SequenceNumLength = 2;
    
    get identifier() {
        return this.packet.getUint16(ICMPEchoRequest._IdentifierOffset);
    }

    get sequenceNum() {
        return this.packet.getUint16(ICMPEchoRequest._SequenceNumOffset);
    }

    get data() {
        let ret = "";
		for (let i = ICMPEchoRequest._DataOffset; i < this.packet.byteLength; i++) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0");
		}
		return ret;
    }

    get toString() {
        return `Echo Request, Identifier: ${this.identifier}, Sequence: ${this.sequenceNum}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Echo Request (8)`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Identifier", `${this.identifier}`, defaultState, byteOffset + ICMPEchoRequest._IdentifierOffset, ICMPEchoRequest._IdentifierLength));
		element.children.push(new Node("Sequence", `${this.sequenceNum}`, defaultState, byteOffset + ICMPEchoRequest._SequenceNumOffset, ICMPEchoRequest._SequenceNumLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Data", `${this.data}`, defaultState, byteOffset + ICMPEchoRequest._DataOffset, this.packet.byteLength - ICMPEchoRequest._DataOffset));
		return [element];
	}
}

class ICMPEchoReply extends ICMPMessage {
	protected static readonly _IdentifierOffset = 4;
	protected static readonly _SequenceNumOffset = 6;
	protected static readonly _DataOffset = 8;

    protected static readonly _IdentifierLength = 2;
	protected static readonly _SequenceNumLength = 2;
    
    get identifier() {
        return this.packet.getUint16(ICMPEchoReply._IdentifierOffset);
    }

    get sequenceNum() {
        return this.packet.getUint16(ICMPEchoReply._SequenceNumOffset);
    }

    get data() {
        let ret = "";
		for (let i = 8; i < this.packet.byteLength; i++) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0");
		}
		return ret;
    }

    get toString() {
        return `Echo Reply, Identifier: ${this.identifier}, Sequence: ${this.sequenceNum}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Echo Reply (0)`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Identifier", `${this.identifier}`, defaultState, byteOffset + ICMPEchoReply._IdentifierOffset, ICMPEchoReply._IdentifierLength));
		element.children.push(new Node("Sequence", `${this.sequenceNum}`, defaultState, byteOffset + ICMPEchoReply._SequenceNumOffset, ICMPEchoReply._SequenceNumLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		element.children.push(new Node("Data", `${this.data}`, defaultState, byteOffset + ICMPEchoReply._DataOffset, this.packet.byteLength - ICMPEchoReply._DataOffset));
		return [element];
	}
}

class ICMPTimestamp extends ICMPMessage {
	protected static readonly _originalTimestampOffset = 4;
	protected static readonly _receiveTimestampOffset = 8;
	protected static readonly _transmitTimestampOffset = 12;

    protected static readonly _TimestampLength = 4;
    
    get originateTimestamp() {
        return this.packet.getUint32(ICMPTimestamp._originalTimestampOffset);
    }

    get receiveTimestamp() {
        return this.packet.getUint32(ICMPTimestamp._receiveTimestampOffset);
    }

    get transmitTimestamp() {
        return this.packet.getUint32(ICMPTimestamp._transmitTimestampOffset);
    }

    get toString() {
        return `Timestamp: Originate: ${this.originateTimestamp}, Receive: ${this.receiveTimestamp}, Transmit: ${this.transmitTimestamp}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Timestamp (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Originate Timestamp", `${this.originateTimestamp}`, defaultState, byteOffset + ICMPTimestamp._originalTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Receive Timestamp", `${this.receiveTimestamp}`, defaultState, byteOffset + ICMPTimestamp._receiveTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Transmit Timestamp", `${this.transmitTimestamp}`, defaultState, byteOffset + ICMPTimestamp._transmitTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		return [element];
	}
}

class ICMPTimestampReply extends ICMPTimestamp {
    get toString() {
        return `Timestamp Reply: Originate: ${this.originateTimestamp}, Receive: ${this.receiveTimestamp}, Transmit: ${this.transmitTimestamp}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Timestamp Reply (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Originate Timestamp", `${this.originateTimestamp}`, defaultState, byteOffset + ICMPTimestamp._originalTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Receive Timestamp", `${this.receiveTimestamp}`, defaultState, byteOffset + ICMPTimestamp._receiveTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Transmit Timestamp", `${this.transmitTimestamp}`, defaultState, byteOffset + ICMPTimestamp._transmitTimestampOffset, ICMPTimestamp._TimestampLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		return [element];
	}
}

class ICMPInformationRequest extends ICMPMessage {
    get toString() {
        return `Information Request`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Information Request (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		return [element];
	}
}

class ICMPInformationReply extends ICMPMessage {
    get toString() {
        return `Information Reply`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Information Reply (${this.type})`, defaultState, byteOffset + ICMPMessage._TypeOffset, ICMPMessage._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPMessage._CodeOffset, ICMPMessage._CodeLength));
		element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPMessage._ChecksumOffset, ICMPMessage._ChecksumLength));
		return [element];
	}
}

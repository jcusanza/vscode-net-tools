import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { Address6 } from "ip-address";

export class ICMPv6Packet extends GenericPacket {
    public static readonly Name = "ICMPv6";
	packet: DataView;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;
        this.registerProtocol(ICMPv6Packet.Name, fc);

	}

    get message(): ICMPv6Message {
        return ICMPv6Message.create(this.packet);
    }

	get toString() {
		return `ICMPv6 ${this.message.toString} `;
	}

    get getProperties() {
        return this.message.getProperties;
    }
}

class ICMPv6Message {
	protected static readonly _TypeOffset = 0;
	protected static readonly _CodeOffset = 1;
	protected static readonly _ChecksumOffset = 2;

	protected static readonly _TypeLength = 1;
	protected static readonly _CodeLength = 1;
	protected static readonly _ChecksumLength = 2;

    packet: DataView;

    constructor(dv:DataView) {
        this.packet = dv;
    }

    static create(dv: DataView): ICMPv6Message {
        if(dv.getUint8(0) < 128 ) {
            return ICMPv6Error.create(dv);
        } else {
            return ICMPv6Info.create(dv);
        }
    }

    get type() {
        return this.packet.getUint8(ICMPv6Message._TypeOffset);
    }

    get code() {
        return this.packet.getUint8(ICMPv6Message._CodeOffset);
    }

    get checksum() {
        return this.packet.getUint16(ICMPv6Message._ChecksumOffset);
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Unknown (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));

		return [element];
	}
}

class ICMPv6Error extends ICMPv6Message {

    constructor(dv: DataView) {
        super(dv);
    }

    static create(dv:DataView): ICMPv6Error {
        switch(dv.getUint8(0)) {
            case 1:
                return new ICMPv6DestinationUnreachable(dv);
            case 2:
                return new ICMPv6PacketTooBig(dv);
            case 3:
                return new ICMPv6TimeExceeded(dv);
            case 4:
                return new ICMPv6ParameterProblem(dv);
            default:
                return new ICMPv6Error(dv);
        }
    }

    get invokingPacket() {
        return "not done";
    }

    get toString() {
        return `Unknown Error Message (${this.type})`;
    }
    
}

class ICMPv6Info extends ICMPv6Message {

    static create(dv:DataView): ICMPv6Info {
        switch(dv.getUint8(0)) {
            case 128:
                return new ICMPv6EchoRequest(dv);
            case 129:
                return new ICMPv6EchoReply(dv);
            case 135:
                return new ICMPv6NeighborSolicitation(dv);
            case 136:
                return new ICMPv6NeighborAdvertisement(dv);
            default:
                return new ICMPv6Info(dv);
        }
    }

    constructor(dv: DataView) {
        super(dv);
    }

    get toString() {
        return `Unknown Info Message (${this.type})`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Neighbor Solicitation (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));

		return [element];
	}
}

class ICMPv6EchoRequest extends ICMPv6Info {
	protected static readonly _IdentifierOffset = 4;
	protected static readonly _SequenceNumOffset = 6;
	protected static readonly _DataOffset = 8;

	protected static readonly _IdentifierLength = 2;
	protected static readonly _SequenceNumLength = 2;

    constructor(dv: DataView) {
        super(dv);
    }

    get identifier() {
        return this.packet.getUint16(ICMPv6EchoRequest._IdentifierOffset);
    }

    get sequenceNum() {
        return this.packet.getUint16(ICMPv6EchoRequest._SequenceNumOffset);
    }

    get data() {
        let ret = "";
		for (let i = ICMPv6EchoRequest._DataOffset; i < this.packet.byteLength; i++) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0") + " ";
		}
		return ret;
    }

    get toString() {
        return `Echo Request, Identifier: ${this.code} Sequence Num: ${this.sequenceNum} Data: ${this.data}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Echo Request (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Identifier", `0x${this.identifier.toString(16)}`, defaultState, byteOffset + ICMPv6EchoRequest._IdentifierOffset, ICMPv6EchoRequest._IdentifierLength));
		element.children.push(new Node("Sequence", `${this.sequenceNum}`, defaultState, byteOffset + ICMPv6EchoRequest._SequenceNumOffset, ICMPv6EchoRequest._SequenceNumLength));
        element.children.push(new Node("Data", `${this.data}`, defaultState, byteOffset + ICMPv6EchoRequest._DataOffset, this.packet.byteLength - ICMPv6EchoRequest._DataOffset));
		return [element];
	}
}

class ICMPv6EchoReply extends ICMPv6Info {
	protected static readonly _IdentifierOffset = 4;
	protected static readonly _SequenceNumOffset = 6;
	protected static readonly _DataOffset = 8;

	protected static readonly _IdentifierLength = 2;
	protected static readonly _SequenceNumLength = 2;

    constructor(dv: DataView) {
        super(dv);
    }

    get identifier() {
        return this.packet.getUint16(ICMPv6EchoReply._IdentifierOffset);
    }

    get sequenceNum() {
        return this.packet.getUint16(ICMPv6EchoReply._SequenceNumOffset);
    }

    get data() {
        let ret = "";
		for (let i = ICMPv6EchoReply._DataOffset; i < this.packet.byteLength; i++) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0") + " ";
		}
		return ret.trimEnd();
    }

    get toString() {
        return `Echo Reply, Identifier: ${this.code} Sequence Num: ${this.sequenceNum} Data: ${this.data}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Echo Reply (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Identifier", `0x${this.identifier.toString(16)}`, defaultState, byteOffset + ICMPv6EchoReply._IdentifierOffset, ICMPv6EchoReply._IdentifierLength));
		element.children.push(new Node("Sequence", `${this.sequenceNum}`, defaultState, byteOffset + ICMPv6EchoReply._SequenceNumOffset, ICMPv6EchoReply._SequenceNumLength));
        element.children.push(new Node("Data", `${this.data}`, defaultState, byteOffset + ICMPv6EchoReply._DataOffset, this.packet.byteLength - ICMPv6EchoReply._DataOffset));
		return [element];
	}
}

class ICMPv6NeighborSolicitation extends ICMPv6Info {
    protected static readonly _ReservedOffset = 4;
    protected static readonly _TargetAddressOffset = 8;
	protected static readonly _OptionOffset = 24;

	protected static readonly _ReservedLength = 4;
	protected static readonly _TargetAddressLength = 16;
	protected static readonly _OptionLength = 6;

    constructor(dv: DataView) {
        super(dv);
    }

    get targetAddress() {
        const AddressOffset = this.packet.byteOffset + ICMPv6NeighborSolicitation._TargetAddressOffset;
        const a = this.packet.buffer.slice(AddressOffset, AddressOffset+ICMPv6NeighborSolicitation._TargetAddressLength);
		const ua = new Uint8Array(a);
		const na = Array.from(ua);
		return Address6.fromByteArray(na);
    }   

    get option() {
        if(this.packet.byteLength <= ICMPv6NeighborSolicitation._OptionOffset) {
            return undefined;
        }

        let ret = "";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 2).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 3).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 4).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 5).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 6).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborSolicitation._OptionOffset + 7).toString(16).padStart(2, "0");
			
		return ret;
    }
    


    get toString() {
        return `Neighbor Solicitation for ${this.targetAddress.correctForm()}${this.option ? ` from ${this.option}` : ""}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Neighbor Solicitation (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Reserved", `00000000`, defaultState, byteOffset + ICMPv6NeighborSolicitation._ReservedOffset, ICMPv6NeighborSolicitation._ReservedLength));
		element.children.push(new Node("Target Address", `${this.targetAddress.correctForm()}`, defaultState, byteOffset + ICMPv6NeighborSolicitation._TargetAddressOffset, ICMPv6NeighborSolicitation._TargetAddressLength));
        element.children.push(new Node("ICMPv6 Option", `Source link-layer address ${this.option}`, defaultState, byteOffset + ICMPv6NeighborSolicitation._OptionOffset, ICMPv6NeighborSolicitation._OptionLength));
		return [element];
	}
}

class ICMPv6NeighborAdvertisement extends ICMPv6Info {
    protected static readonly _FlagsOffset = 4;
    protected static readonly _ReservedOffset = 5;
	protected static readonly _TargetAddressOffset = 8;
	protected static readonly _OptionOffset = 24;

	protected static readonly _FlagsLength = 1;
    protected static readonly _ReservedLength = 3;
	protected static readonly _TargetAddressLength = 16;
	protected static readonly _OptionLength = 6;
    
    constructor(dv: DataView) {
        super(dv);
    }

    get r() {
        return this.packet.getUint8(4) >> 7 !== 0;
    }

    get s() {
        return (this.packet.getUint8(4) && 0x40) !==0;
    }

    get o() {
        return (this.packet.getUint8(4) && 0x20) !==0;
    }

    get getFlags(): string {
		let buffer: string = "";
		if(this.r) {
			buffer += "Reserved";
		}
        if(this.r && this.s) {
            buffer += ", ";
        }
        if(this.s) {
			buffer += "Solicited";
		}
        if(this.o && (this.r || this.s)) {
            buffer += ", ";
        }
        if(this.o) {
			buffer += "Override";
		}
		return buffer.trimEnd();
	}

    get targetAddress() {
        const AddressOffset = this.packet.byteOffset + ICMPv6NeighborAdvertisement._TargetAddressOffset;
        const a = this.packet.buffer.slice(AddressOffset, AddressOffset+ICMPv6NeighborAdvertisement._TargetAddressLength);
		const ua = new Uint8Array(a);
		const na = Array.from(ua);
		return Address6.fromByteArray(na);
    }   

    get option() {
        if(this.packet.byteLength <= ICMPv6NeighborAdvertisement._OptionOffset) {
            return undefined;
        }

        let ret = "";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 2).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 3).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 4).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 5).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 6).toString(16).padStart(2, "0") + ":";
        ret += this.packet.getUint8(ICMPv6NeighborAdvertisement._OptionOffset + 7).toString(16).padStart(2, "0");
			
		return ret;
    }
    


    get toString() {
        let flags: string = "";
		if(this.r) {
			flags += "res";
		}
        if(this.r && this.s) {
            flags += ", ";
        }
        if(this.s) {
			flags += "sol";
		}
        if(this.o && (this.r || this.s)) {
            flags += ", ";
        }
        if(this.o) {
			flags += "ovr";
		}
        return `Neighbor Advertisement ${this.targetAddress.correctForm()} (${flags.trimEnd()})${this.option ? ` is at ${this.option}` : ""}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Neighbor Advertisement (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Flags", `${this.getFlags}`, defaultState, byteOffset + ICMPv6NeighborAdvertisement._FlagsOffset, ICMPv6NeighborAdvertisement._FlagsLength));
        element.children.push(new Node("Reserved", `000000`, defaultState, byteOffset + ICMPv6NeighborAdvertisement._ReservedOffset, ICMPv6NeighborAdvertisement._ReservedLength));
        element.children.push(new Node("Target Address", `${this.targetAddress.correctForm()}`, defaultState, byteOffset + ICMPv6NeighborAdvertisement._TargetAddressOffset, ICMPv6NeighborAdvertisement._TargetAddressLength));
        element.children.push(new Node("ICMPv6 Option", `Target link-layer address ${this.option}`, defaultState, byteOffset + ICMPv6NeighborAdvertisement._OptionOffset, ICMPv6NeighborAdvertisement._OptionLength));
		return [element];
	}
}

class ICMPv6DestinationUnreachable extends ICMPv6Error {
    
    constructor(dv: DataView) {
        super(dv);
    }

    get codeMessage() {
        switch(this.code) {
            case 0:
                return "No route to destination";
            case 1:
                return "Communication with destination administratively prohibited";
            case 2:
                return "Beyond scope of source address";
            case 3:
                return "Address unreachable";
            case 4:
                return "Port unreachable";
            case 5:
                return "Source address failed ingress/egress policy";
            case 6:
                return "Reject route to destination";
            default:
                return;

        }
    }

    get toString() {
        return `Destination Unreachable Error: ${this.codeMessage}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Destination Unreachable (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.codeMessage} (${this.code})`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Invoking Packet", `${this.invokingPacket}`));
		return [element];
	}
}

class ICMPv6PacketTooBig extends ICMPv6Error {
    protected static readonly _MTUOffset = 4;

	protected static readonly _MTULength = 4;

    constructor(dv: DataView) {
        super(dv);
    }

    get mtu() {
        return this.packet.getUint32(ICMPv6PacketTooBig._MTUOffset);
    }

    get toString() {
        return `Packet Too Big Error`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Packet Too Big (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.code}`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
		element.children.push(new Node("MTU", `${this.mtu}`, defaultState, byteOffset + ICMPv6PacketTooBig._MTUOffset, ICMPv6PacketTooBig._MTULength));
        element.children.push(new Node("Invoking Packet", `${this.invokingPacket}`));
		return [element];
	}
}

class ICMPv6TimeExceeded extends ICMPv6Error {
    
    constructor(dv: DataView) {
        super(dv);
    }

    get codeMessage() {
        switch(this.code) {
            case 0:
                return "Hop limit exceeded in transit";
            case 1:
                return "Fragment reassembly time exceeded";
            default:
                return;

        }
    }

    get toString() {
        return `Time Exceeded Error: ${this.codeMessage}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Time Exceeded (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.codeMessage} (${this.code})`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Invoking Packet", `${this.invokingPacket}`));
		return [element];
	}
}

class ICMPv6ParameterProblem extends ICMPv6Error {
    
    constructor(dv: DataView) {
        super(dv);
    }
    
    get pointer() {
        return this.packet.getUint32(4);
    }

    get codeMessage() {
        switch(this.code) {
            case 0:
                return "Erroneous header field encountered";
            case 1:
                return "Unrecognized Next Header type encountered";
            case 2:
                return "Unrecognized IPv6 option encountered";
            default:
                return;

        }
    }

    get toString() {
        return `Parameter Problem Error: ${this.codeMessage}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

        const element = new Node("Internet Control Message Protocol v6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.packet.byteLength);
		element.children.push(new Node("Type", `Parameter Problem (${this.type})`, defaultState, byteOffset + ICMPv6Message._TypeOffset, ICMPv6Message._TypeLength));
		element.children.push(new Node("Code", `${this.codeMessage} (${this.code})`, defaultState, byteOffset + ICMPv6Message._CodeOffset, ICMPv6Message._CodeLength));
        element.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + ICMPv6Message._ChecksumOffset, ICMPv6Message._ChecksumLength));
        element.children.push(new Node("Invoking Packet", `${this.invokingPacket}`));
		return [element];
	}
}

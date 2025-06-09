import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

enum TLSContentTypes {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23
}

enum TLSHandshakeMessageTypes {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254 
}


let TLSHandshakeMessageNames = new Map<number, string>([
	[TLSHandshakeMessageTypes.client_hello, "Client Hello"],
    [TLSHandshakeMessageTypes.server_hello,"Server Hello"],
    [TLSHandshakeMessageTypes.new_session_ticket,"New Session Ticket"],
    [TLSHandshakeMessageTypes.end_of_early_data,"End of Early Data"],
    [TLSHandshakeMessageTypes.encrypted_extensions,"Encrypted Extensions"],
    [TLSHandshakeMessageTypes.certificate,"Certificate"],
    [TLSHandshakeMessageTypes.certificate_request,"Certificate Request"],
    [TLSHandshakeMessageTypes.certificate_verify,"Certificate Verify"],
    [TLSHandshakeMessageTypes.finished,"Finished"],
    [TLSHandshakeMessageTypes.key_update,"Key Update"],
    [TLSHandshakeMessageTypes.message_hash,"Message Hash"]
	]);



export class TLSPacket extends GenericPacket {
	public static readonly Name = "TLS";

	static CreateTLSPacket(packet:DataView, fc:FileContext):GenericPacket {
        const contentType = packet.getUint8(0);

        switch (contentType) {
            case TLSContentTypes.change_cipher_spec:
                return new TLSChangeCipherSpec(packet, fc);
            case TLSContentTypes.alert:
                return new TLSAlert(packet, fc);
            case TLSContentTypes.handshake:
                const messageType = packet.getUint8(5);
                switch (messageType) {
                    case TLSHandshakeMessageTypes.client_hello: 
                        return new TLSClientHello(packet, fc);
                    case TLSHandshakeMessageTypes.server_hello:
                        return new TLSServerHello(packet, fc);
                    case TLSHandshakeMessageTypes.new_session_ticket:
                        return new TLSNewSessionTicket(packet, fc);
                    case TLSHandshakeMessageTypes.end_of_early_data:
                        return new TLSEndOfEarlyData(packet, fc);
                    case TLSHandshakeMessageTypes.encrypted_extensions:
                        return new TLSEncryptedExtensions(packet, fc);
                    case TLSHandshakeMessageTypes.certificate:
                        return new TLSCertificate(packet, fc);
                    case TLSHandshakeMessageTypes.certificate_request:
                        return new TLSCertificateRequest(packet, fc);
                    case TLSHandshakeMessageTypes.certificate_verify:
                        return new TLSCertificateVerify(packet, fc);
                    case TLSHandshakeMessageTypes.finished:
                        return new TLSFinished(packet, fc);
                    case TLSHandshakeMessageTypes.key_update:
                        return new TLSKeyUpdate(packet, fc);
                    case TLSHandshakeMessageTypes.message_hash:   
                        return new TLSMessageHash(packet, fc);
                }
            case TLSContentTypes.application_data:
                return new TLSApplicationData(packet, fc);
            default:
                return new TLSRecord(packet, fc);
        }
    }
}


// #region TLSRecord

export class TLSRecord extends GenericPacket {
    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(TLSPacket.Name, fc);
	}

    get ContentType(){
        return this.packet.getUint8(0);
    }

	get ContentTypeText(){
        switch (this.ContentType) {
			case TLSContentTypes.change_cipher_spec:
				return "Change Cipher Spec";
			case TLSContentTypes.alert:
				return "Alert";
			case TLSContentTypes.application_data:
				return "Application Data";
			case TLSContentTypes.handshake:
				return "Handshake";
		};
    }

    get RecordProtocolVersion() {
        return this.packet.getUint16(1);
    }

	get RecordProtocolVersionName() {
        switch (this.RecordProtocolVersion) {
			case 0x301:
				return "TLS 1.0";
			case 0x303:
				return "TLS 1.3";
			default:
				return "TLS ?.?";	
		};
    }

    get RecordLength() {
        return this.packet.getUint16(3);
    }

    get toString() {
		return `TLS Record`;
	}

	get getProperties(): Node[] {
		const e = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		const e2 = new Node("TLS Record Layer", ``, vscode.TreeItemCollapsibleState.Collapsed);
		e2.children.push(new Node("Content Type", `${this.ContentTypeText} (${this.ContentType})`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		e2.children.push(new Node("Version", `${this.RecordProtocolVersionName} (0x${this.RecordProtocolVersion.toString(16)})`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		e2.children.push(new Node("Length", `${this.RecordLength}`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		e.children.push(e2);
		return [e];
	}
}

// #region TLSChangeCipherSpec

export class TLSChangeCipherSpec extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `TLS Change Cipher Spec`;
	}

	get getProperties(): Node[] {
		const e = super.getProperties;
		return e;
	}

}

// #region TLSApplicationData

export class TLSApplicationData extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `TLS Application Data`;
	}

	get getProperties(): Node[] {
		const e = super.getProperties;
		return e;
	}

}

// #region TLSAlert

export class TLSAlert extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get AlertLevel(){
        return this.packet.getUint8(this.offset + 0);
    }

    get AlertDescription() {
        return this.packet.getUint8(this.offset + 1);
    }

    get toString() {
		return `TLS Alert`;
	}


	get getProperties(): Node[] {
		const e = super.getProperties;
		return e;
	}

}

// #region Handshake

export class TLSHandshake extends TLSRecord {
    private static HandshakeOffset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get MessageType(){
        return this.packet.getUint8(TLSHandshake.HandshakeOffset + 0);
    }

	get MessageTypeText():string {
		const val = TLSHandshakeMessageNames.get(this.MessageType);
		return val === undefined ? "" : val;
	}

    get Length() {
        return this.packet.getUint32(TLSHandshake.HandshakeOffset + 0) & 0xFFFFFF;
    }

    get toString() {
		return `TLS Handshake`;
	}


	get getProperties(): Node[] {
		const e = super.getProperties;
		const e2 = new Node("Handshake Protocol", this.MessageTypeText, vscode.TreeItemCollapsibleState.Collapsed);
		e2.children.push(new Node("Handshake Type", `${this.MessageTypeText} (${this.MessageType})`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		e2.children.push(new Node("Length", `${this.Length}`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		e[e.length-1].children[e[e.length-1].children.length-1].children.push(e2);
		return e;
	}

}

// #region Client Hello

export class TLSClientHello extends TLSHandshake {
    private static ClientHelloOffset:number = 9;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get ProtocolVersion() {
        return this.packet.getUint16(TLSClientHello.ClientHelloOffset);
    }

	get ProtocolVersionName() {
        switch (this.ProtocolVersion) {
			case 0x301:
				return "TLS 1.0";
			case 0x303:
				return "TLS 1.2";
			default:
				return "TLS ?.?";	
		};
    }

	get Random() {
		return "";
	}
	get toString() {
		return `TLS Client Hello`;
	}

	get getProperties(): Node[] {
		const e = super.getProperties; //top/TLS/Record/Handshake
		const tls = e[e.length-1].children;
		const record = tls[tls.length-1].children;
		const handshake = record[record.length-1].children;
		handshake.push(new Node("Version", `${this.ProtocolVersionName} (0x${this.ProtocolVersion.toString(16)})`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));
		handshake.push(new Node("Random", `${this.ProtocolVersionName} (0x${this.ProtocolVersion.toString(16)})`, vscode.TreeItemCollapsibleState.None, this.packet.byteOffset+6, 6));

		return e;
	}

}

// #region Server Hello

export class TLSServerHello extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Server Hello`;
	}

	get getProperties(): Array<any> {
		const arr: Array<any> = [
            `*Transport Layer Security`,
        ];

		return arr;
	}
}

// #region New Session Ticket

export class TLSNewSessionTicket extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS New Session Ticket`;
	}


	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region End of Early Data

export class TLSEndOfEarlyData extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS End of Early Data`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Encrypted Extensions

export class TLSEncryptedExtensions extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Encrypted Extensions`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region Certificate

export class TLSCertificate extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Certificate Request

export class TLSCertificateRequest extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate Request`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Certificate Verify

export class TLSCertificateVerify extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate Verify`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Finished

export class TLSFinished extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Finished`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Key Update

export class TLSKeyUpdate extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Key Update`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region Message Hash

export class TLSMessageHash extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Message Hash`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}



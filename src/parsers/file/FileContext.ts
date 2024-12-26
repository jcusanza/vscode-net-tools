import { GenericPacket, PacketState } from "../packet/genericPacket";
import { Section, PCAPHeaderRecord, PCAPNGSectionHeaderBlock } from "./section";


export enum FileType{
    Unknown,
    PCAP,
    PCAPNG
};

export class FileContext {
    private _fileType = FileType.Unknown;
    private _le = true;
    private _bytes:Uint8Array;

    private _currentHeader?:PCAPHeaderRecord|PCAPNGSectionHeaderBlock = undefined;
    public states:PacketState[] = [];

    public protocols = new Map<string, Section[]>();
    public addresses = new Map<string, Section[]>();

    private _lastSection?:Section = undefined;
    private _thisSection?:Section = undefined;
    
    public headers:GenericPacket[] = [];

    constructor(bytes: Uint8Array) {
        this._bytes = bytes;
    }

    get IsInitialized():boolean {
        return this._fileType !== FileType.Unknown;
    }

    SetHeader(newSection:PCAPHeaderRecord|PCAPNGSectionHeaderBlock, le:boolean, type:FileType)
    {
        this._currentHeader = newSection;

        this._le = le;
        this._fileType = type;
    }

    get header():PCAPHeaderRecord|PCAPNGSectionHeaderBlock {
        if (this._currentHeader === undefined) {
            throw new Error("Current header is undefined");
        }
        return this._currentHeader;
    }

    set lastSection(value:Section) {
        this._lastSection = value;
    }

    get lastSection():Section {
        if (this._lastSection === undefined) {
            throw new Error("Last section is undefined");
        }
        return this._lastSection;
    }

    set thisSection(value:Section) {
        this._thisSection = value;
    }

    get thisSection():Section {
        if (this._thisSection === undefined) {
            throw new Error("This section is undefined");
        }
        return this._thisSection;
    }


    get bytes():Uint8Array {
        return this._bytes;
    }

    set le(value:boolean) {
        this._le = value;
    }

    get le():boolean {
        return this._le;
    }

    get fileType():FileType {
        return this._fileType;
    } 
}
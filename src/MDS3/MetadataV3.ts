
type AAID = string;

type AAGUID = string;

type alternativeDescriptionsType = {
    [languageCode: string] : string;
}

type upvType = {
    major: number;
    minor: number;
}

type rgbPaletteEntry = {
    r: number
    g: number;
    b: number;
}

type tcDisplayPNGCharacteristicsType = {
    width: number;
    height: number;
    bitDepth: number;
    colorType: number;
    compression: number;
    filter: number;
    interlace: number;
    plte?: rgbPaletteEntry[];
};

type caDescType = {
    base: number;
    minLength: number;
    maxRetries?: number;
    blockSlowdown?: number;
};

type baDescType = {
    selfAttestedFRR?: number;
    selfAttestedFAR?: number;
    maxTemplates?: number;
    maxRetries?: number;
    blockSlowdown?: number;
};

type paDescType = {
    minComplexity: number;
    maxRetries?: number;
    blockSlowdown?: number;
}

type userVerificationDetailsType = {
    userVerification: number;
    caDesc?: caDescType;
    baDesc?: baDescType;
    paDesc?: paDescType;
};

type ecdaaTrustAnchorsType = {
    X: string;
    Y: string;
    c: string;
    sx: string;
    sy: string;
    G1Curve: string;
};

type supportedExtensionsType = {
    id: string;
    tag?: number;
    data?: string;
    fail_if_unknown: boolean;
};

enum authAlgorithm {
    'secp256r1_ecdsa_sha256_raw' = 1,
    'secp256r1_ecdsa_sha256_der',
    'rsassa_pss_sha256_raw',
    'rsassa_pss_sha256_der',
    'secp256k1_ecdsa_sha256_raw',
    'secp256k1_ecdsa_sha256_der',
    'sm2_sm3_raw',
    'rsa_emsa_pkcs1_sha256_raw',
    'rsa_emsa_pkcs1_sha256_der',
    'rsassa_pss_sha384_raw',
    'rsassa_pss_sha512_raw',
    'rsassa_pkcsv15_sha256_raw',
    'rsassa_pkcsv15_sha384_raw',
    'rsassa_pkcsv15_sha512_raw',
    'rsassa_pkcsv15_sha1_raw',
    'secp384r1_ecdsa_sha384_raw',
    'secp512r1_ecdsa_sha256_raw',
    'ed25519_eddsa_sha512_raw'
};

enum PKAlgAndEncodings {
    'ecc_x962_raw' = 256,
    'ecc_x962_der',
    'rsa_2048_raw',
    'rsa_2048_der',
    'cose'
};

enum attestations {
    'basic_full' = 15879,
    'basic_surrogate',
    'ecdaa',
    'attca'
};

enum KProtection {
    'software' = 1,
    'hardware' = 2,
    'tee' = 4,
    'secure_element' = 8,
    'remote_handle' = 16
};

enum matcher {
    'software' = 1,
    'tee' = 2,
    'on_chip' = 4
};

enum attachmentHintValues {
    'internal' = 1,
    'external' = 2,
    'wired' = 4,
    'wireless' = 8,
    'nfc' = 16,
    'bluetooth' = 32,
    'network' = 64,
    'ready' = 128,
    'wifi_direct' = 256
};

enum tcDisplayValues {
    'any' = 1,
    'privileged_software' = 2,
    'tee' = 4,
    'hardware' = 8,
    'remote' = 16
};

enum userVerificationValues {
    'presence_internal' = 1,
    'fingerprint_internal' = 2,
    'passcode_internal' = 4,
    'voiceprint_internal' = 8,
    'faceprint_internal' = 16,
    'location_internal' = 32,
    'eyeprint_internal' = 64,
    'pattern_internal' = 128,
    'handprint_internal' = 256,
    'passcode_external' = 2048,
    'pattern_external' = 4096,
    'none' = 512,
    'all' = 1024
};

class MetadataV3 {
    private constructor() {}

    public static initialize<T extends MetadataV3>(data: T): MetadataV3 {
        const result = new MetadataV3();
        const dataJson = JSON.stringify(data);
        Object.assign(result, JSON.parse(dataJson));
        return result;
    }

    private legalHeader?: string;
    public getLegalHeader() {
        return this.legalHeader;
    }
    public setLegalHeader(legalHeader: string) {
        this.legalHeader = legalHeader;
    }
    public validateLegalHeader(): boolean {
        if (!this.legalHeader) { return true; }
        try {
          new URL(this.legalHeader);
          return true;
        } catch (error) {
          return false;
        }
    }   

    private aaid?: AAID;
    public getAAID(): string | undefined {
        return this.aaid;
    }
    public setAAID(aaid: string) {
        this.aaid = aaid;
    }
    public validateAAID(): boolean {
        if(this.getProtocolFamily() === 'uaf' && !this.getAAGUID()) {
            if(this.aaid) {
                const aaidPattern = /\d{4}[#]\d{4}/;
                return aaidPattern.test(this.aaid);
            }
            return false;
        }
        if(this.aaid) {
            return false;
        } else {
            return true;
        }
    }

    private aaguid?: AAGUID;
    public getAAGUID(): string | undefined {
        return this.aaguid;
    }
    public setAAGUID(aaguid: string) {
        this.aaguid = aaguid;
    }
    public validateAAGUID(): boolean {
        if(this.getProtocolFamily() === 'fido2' && !this.getAAID()) {
            if(this.aaguid) {
                // Regular expression to match UUID (8-4-4-4-12 format)
                const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                return uuidPattern.test(this.aaguid);
            }
            return false;
        }
        if(this.aaguid) {
            return false;
        } else {
            return true;
        }
    }
      

    private attestationCertificateKeyIdentifiers?: string[];
    public getAttestationCertificateKeyIdentifiers(): string[] | undefined {
        return this.attestationCertificateKeyIdentifiers;
    }
    public setAttestationCertificateKeyIdentifiers(attestationCertificateKeyIdentifiers: string[]) {
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
    }
    public validateAttestationCertificateKeyIdentifiers(): boolean {
        if(!this.getAAID() && !this.getAAGUID()) {
            if(this.attestationCertificateKeyIdentifiers) {
                const hexPattern = /^[0-9a-f]+$/;
                for (const identifier of this.attestationCertificateKeyIdentifiers) {
                    if (!hexPattern.test(identifier)) {
                    return false;
                    }
                }
                return true;
            }
            return false;
        }
        if(this.attestationCertificateKeyIdentifiers) {
            return false;
        } else {
            return true;
        }
    }

    private description: string = "";
    public getDescription(): string {
        return this.description;
    }
    public setDescription(description: string) {
        this.description = description;
    }
    public validateDescription(): boolean {
        return !!this.description;
    }

    private alternativeDescriptions?: alternativeDescriptionsType;
    public getAlternativeDescriptions() : alternativeDescriptionsType | undefined {
        return this.alternativeDescriptions;
    }
    public setAlternativeDescriptions(alternativeDescriptions: alternativeDescriptionsType) {
        this.alternativeDescriptions = alternativeDescriptions;
    }
    public validateAlternativeDescriptions(): boolean {
        if (!this.alternativeDescriptions) { return true; }
      
        // Check if all values in alternativeDescriptions are strings
        for (const languageCode in this.alternativeDescriptions) {
          if (!this.alternativeDescriptions.hasOwnProperty(languageCode)) {
            continue;
        }
      
        const description = this.alternativeDescriptions[languageCode];
        if (typeof description !== 'string') {
            return false;
        }
        }
        return true;
    }
      

    private authenticatorVersion: number = 0;
    public getAuthenticatorVersion() : number {
        return this.authenticatorVersion;
    }
    public setAuthenticatorVersion(authenticatorVersion: number) {
        this.authenticatorVersion = authenticatorVersion;
    }
    public validateAuthenticatorVersion(): boolean {
      
        // Check if authenticatorVersion is a positive whole number within the range of an unsigned 16-bit integer
        return Number.isInteger(this.authenticatorVersion) && this.authenticatorVersion >= 0 && this.authenticatorVersion <= 65535;
    }  

    private protocolFamily: string = '';
    public getProtocolFamily(): string | undefined {
        return this.protocolFamily;
    }
    public setProtocolFamily(protocolFamily: string) {
        this.protocolFamily = protocolFamily;
    }
    public validateProtocolFamily(): boolean {
        if (this.protocolFamily == '') { return false; }
        
        const validValues = ['uaf', 'u2f', 'fido2'];
        
        return validValues.includes(this.protocolFamily);
    }

    private schema: number = 3;
    public getSchema(): number {
        return this.schema;
    }
    public setSchema(schema: number) {
        this.schema = schema;
    }
    public validateSchema(): boolean {
        return this.schema == 3 ? true : false;
    }

    //campo dati marcato come readonly, non ha quindi senso mettere un setter
    private upv: upvType[] = [];
    public getUpv(): upvType[] {
        return this.upv;
    }
    public validateUpv(): boolean {
        if (!Array.isArray(this.upv) || this.upv.length === 0) {
            return false;
        }

        for (const version of this.upv) {
            if (!(Number.isInteger(this.authenticatorVersion) && this.authenticatorVersion >= 0 && this.authenticatorVersion <= 65535)) {
              return false;
            }
        }
        return true;
    }

    private authenticationAlgorithms: string[] = [];
    public getAuthenticationAlgorithms(): string[] | undefined {
        return this.authenticationAlgorithms;
    }
    public setAuthenticationAlgorithms(authenticationAlgorithms: string[]) {
        this.authenticationAlgorithms = authenticationAlgorithms;
    }
    public validateAuthenticationAlgorithms(): boolean {
        if(this.authenticationAlgorithms.length == 0) { return false; }

        for (const algorithm of this.authenticationAlgorithms) {
            if(!(algorithm in authAlgorithm)) {
                return false;
            }
        }
        return true;
    }

    private publicKeyAlgAndEncodings: string[] = [];
    public getPublicKeyAlgAndEncodings(): string[] {
        return this.publicKeyAlgAndEncodings;
    }
    public setPublicKeyAlgAndEncodings(publicKeyAlgAndEncodings: string[]) {
        this.publicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
    }
    public validatePublicKeyAlgAndEncodings(): boolean {
        if(this.publicKeyAlgAndEncodings.length == 0) { return false; }

        for (const encoding of this.publicKeyAlgAndEncodings) {
            if (!(encoding in PKAlgAndEncodings)) {
                return false;
            }
        }
        return true;
    }

    private attestationTypes: string[] = [];
    public getAttestationTypes(): string[] {
        return this.attestationTypes;
    }
    public setAttestationTypes(attestationTypes: string[]) {
        this.attestationTypes = attestationTypes;
    }
    public validateAttestationTypes(): boolean {
        if(this.attestationTypes.length == 0) { return false; }

        this.attestationTypes.forEach((value) => {
            if(!(value in attestations)) {
                return false;
            }
        })
        return true;
    }

    // userVerificationDetails
    private userVerificationDetails:  userVerificationDetailsType[][] = [[]];
    public getUserVerificationDetails(): userVerificationDetailsType[][] {
        return this.userVerificationDetails;
    }
    public setUserVerificationDetails(userVerificationDetails: userVerificationDetailsType[][]) {
        this.userVerificationDetails = userVerificationDetails;
    }
    public validateUserVerificationDetails(): boolean {
        if(!this.userVerificationDetails) { return false; }
        
        const validUserVerificationValues = [1,2,4,8,16,32,64,128,256,512,1024];

        this.userVerificationDetails.forEach((value) => {
            if(!(value[0].userVerification in userVerificationValues)) {
                return false;
            }
        })

        return true;
    }

    private keyProtection: string[] = [];
    public getKeyProtection(): string[] {
        return this.keyProtection;
    }
    public setKeyProtection(keyProtection: string[]) {
        this.keyProtection = keyProtection;
    }
    public validateKeyProtection(): boolean {
        if(this.keyProtection.length == 0 || this.keyProtection === undefined) { return false; }
    
        this.keyProtection.forEach((value) => {
            console.log(value)
            if(!(value in KProtection)) {
                return false;
            }
        })
        return true;
    } 

    private isKeyRestricted: boolean = true;
    public getIsKeyRestricted(): boolean | undefined {
        return this.isKeyRestricted;
    }
    public setIsKeyRestricted(isKeyRestricted: boolean) {
        this.isKeyRestricted = isKeyRestricted;
    }
    public validateIsKeyRestricted(): boolean {
        return typeof this.isKeyRestricted === 'boolean';
    }

    private isFreshUserVerificationRequired?: boolean;
    public getIsFreshUserVerificationRequired(): boolean | undefined {
        return this.isFreshUserVerificationRequired;
    } 
    public setIsFreshUserVerificationRequired(isFreshUserVerificationRequired: boolean) {
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
    }
    public validateIsFreshUserVerificationRequired(): boolean {
        return typeof this.isFreshUserVerificationRequired === 'undefined' || typeof this.isFreshUserVerificationRequired === 'boolean';
    }

    private matcherProtection: string = '';
    public getMatcherProtection(): string {
        return this.matcherProtection;
    }
    public setMatcherProtection(matcherProtection: string) {
        this.matcherProtection = matcherProtection
    }
    public validateMatcherProtection(): boolean {
        return this.matcherProtection in matcher;
    }

    private cryptoStrength?: number;
    public getCryptoStrength(): number | undefined {
        return this.cryptoStrength;
    }
    public setCryptoStrength(cryptoStrength: number) {
        this.cryptoStrength = cryptoStrength;
    }
    //controlla meglio
    public validateCryptoStrength(): boolean {
        if(!this.cryptoStrength) { return true; }
        return Number.isInteger(this.cryptoStrength) && this.cryptoStrength > 0;
    }

    private operatingEnv?: string;
    public getOperatingEnv(): string | undefined {
        return this.operatingEnv;
    }
    public setOperatingEnv(operatingEnv: string) {
        this.operatingEnv = operatingEnv;
    }
    public validateOperatingEnv(): boolean{
        if(!this.operatingEnv) { return true; }
        const validOperatingEnv = [
            'TEEs based on ARM TrustZone HW',
            'TEE Based on Intel VT HW',
            'TEE Based on Intel SGX HW',
            'TEE Based on Intel ME/TXE HW',
            'TEE with GlobalPlatform TEE Protection Profile Certification',
            'Windows 10 Virtualization-based Security.',
            'Secure World of AMD PSP (Platform Security coProcessor).',
            'Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications.',
            'Secure Element (SE)'
        ]

        return validOperatingEnv.includes(this.operatingEnv);
    }

    private attachmentHint: string = '';
    public getAttachmentHint(): string {
        return this.attachmentHint;
    }
    public setAttachmentHint(attachmentHint: string) {
        this.attachmentHint = attachmentHint;
    }
    public validateAttachmentHint(): boolean {
        return this.attachmentHint in attachmentHintValues;
    }

    //controllare se si può inizializzare meglio
    private isSecondFactorOnly: boolean = false;
    public getIsSecondFactorOnly(): boolean {
        return this.isSecondFactorOnly;
    }
    public setIsSecondFactorOnly(isSecondFactorOnly: boolean) {
        this.isSecondFactorOnly = isSecondFactorOnly;
    }
    public validateIsSecondFactorOnly(): boolean {
        return typeof this.isSecondFactorOnly === 'boolean';
    }

    private tcDisplay?: string[];
    public getTcDisplay(): string[] | undefined {
        return this.tcDisplay;
    }
    public setTcDisplay(tcDisplay: string[]) {
        this.tcDisplay = tcDisplay;
    }
    public validateTcDisplay(): boolean {
        if(!this.tcDisplay) { return true; }

        for(const element in this.tcDisplay) {
            if(!(element in tcDisplayValues)) {
                return false;
            }
        }
        return true;
    }

    private tcDisplayContentType?: string[];
    public getTcDisplayContentType(): string[] | undefined {
        return this.tcDisplayContentType;
    }
    public setTcDisplayContentType(tcDisplayContentType: string[]) {
        this.tcDisplayContentType = tcDisplayContentType;
    }
    public validateTcDisplayContentType(): boolean {
        if(this.getTcDisplay() != undefined && this.getTcDisplay()?.length != 0 && this.validateTcDisplay()) {
            if(this.tcDisplayContentType && this.tcDisplayContentType.length != 0) {
                const allowedContentTypes = ['image/png', 'text/plain'];

                for(const element in this.tcDisplayContentType) {
                    if(!(allowedContentTypes.includes(element))) {
                        return false;
                    }
                }
                return true
            } else {
                return false;
            }
        }
        return false;
    }

    private tcDisplayPNGCharacteristics?: tcDisplayPNGCharacteristicsType[];
    public getTcDisplayPNGCharacteristics(): tcDisplayPNGCharacteristicsType[] | undefined {
        return this.tcDisplayPNGCharacteristics;
    }
    public setTcDisplayPNGCharacteristics(tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsType[]) {
        this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
    }
    public validateTcDisplayPNGCharacteristics(): boolean {
        if(this.getTcDisplay() != undefined && this.getTcDisplay.length != 0 && this.getTcDisplayContentType()?.includes('image/png')) {
            if(this.tcDisplayPNGCharacteristics == undefined) {
                return false; 
            } else {
                const isValidEntry = (entry: tcDisplayPNGCharacteristicsType) => {
                    return (
                      typeof entry.width === 'number' &&
                      typeof entry.height === 'number' &&
                      typeof entry.bitDepth === 'number' &&
                      typeof entry.colorType === 'number' &&
                      typeof entry.compression === 'number' &&
                      typeof entry.filter === 'number' &&
                      typeof entry.interlace === 'number' &&
                      (entry.plte === undefined || (Array.isArray(entry.plte) && entry.plte.length))
                    );
                  };
                
                return this.tcDisplayPNGCharacteristics.every(isValidEntry);
            }

        } else {
            return false;
        }
    }

    private attestationRootCertificates: string[] = [];
    public getAttestationRootCertificates(): string[] {
        return this.attestationRootCertificates;
    }
    public setAttestationRootCertificates(attestationRootCertificates: string[]) {
        this.attestationRootCertificates = attestationRootCertificates;
    }
      
    public validateAttestationRootCertificates(): boolean {
        if(this.attestationRootCertificates.length == 0 || this.attestationRootCertificates === undefined) {
            return false;
        } 

        const { X509Certificate } = require('node:crypto');
        
        for (const certificate of this.attestationRootCertificates) {
            if (typeof certificate !== 'string') {
              return false;
            }
      
            try {
              const certBuffer = Buffer.from(certificate, 'base64');
              const x509Cert = new X509Certificate(certBuffer);
            } catch (error) {
              return false;
            }
        }
        return true;
    }
      

    private ecdaaTrustAnchors?: ecdaaTrustAnchorsType[];
    public getEcdaaTrustAnchors(): ecdaaTrustAnchorsType[] | undefined {
        return this.ecdaaTrustAnchors;
    }
    public setEcdaaTrustAnchors(ecdaaTrustAnchors: ecdaaTrustAnchorsType[]) {
        this.ecdaaTrustAnchors = ecdaaTrustAnchors;
    }
    public validateEcdaaTrustAnchors(): boolean {
        const ecdaa = 15581
        if(this.getAttestationTypes().includes(attestations[ecdaa])) {
            if(this.ecdaaTrustAnchors === undefined) { return false; }
            else {
                if (!this.ecdaaTrustAnchors.every(this.isValidEcdaaTrustAnchor)) {
                    return false;
                }
            }
        }
        return true;
    }
      
    public isValidEcdaaTrustAnchor(trustAnchor: ecdaaTrustAnchorsType): boolean {
        if (
          typeof trustAnchor.X !== 'string' ||
          typeof trustAnchor.Y !== 'string' ||
          typeof trustAnchor.c !== 'string' ||
          typeof trustAnchor.sx !== 'string' ||
          typeof trustAnchor.sy !== 'string' ||
          typeof trustAnchor.G1Curve !== 'string'
        ) {
          return false;
        }
      
        return true;
    }

    private icon?: string;
    public getIcon(): string | undefined {
        return this.icon;
    }
    public setIcon(icon: string) {
        this.icon = icon;
    }
    public validateIcon(): boolean {
        // The icon should be a non-empty string
        if (!this.icon || this.icon.trim() === '') {
            return true;
        }

        // Check if the icon is a valid base64 string
        const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
        if (!base64Regex.test(this.icon)) {
            return false;
        }

            // Helper function to check if a character is a valid base64 character
        const isValidBase64Char = (char: string): boolean => {
            return /^[A-Za-z0-9+/]$/.test(char) || char === '=';
        };

        // Decode the base64 string and check if it is a valid PNG image
        const decodedIcon = this.icon.replace(/=/g, ''); // Remove padding characters ('=')
        let paddingCount = 0;
        for (let i = 0; i < decodedIcon.length; i++) {
            const char = decodedIcon[i];
            if (!isValidBase64Char(char)) {
                return false;
            }
            if (char === '=') {
                paddingCount++;
            }
        }
        // Check if the base64 string length is a multiple of 4 (with or without padding characters)
        if ((decodedIcon.length + paddingCount) % 4 !== 0) {
            return false;
        }
        return true;
    }

    private supportedExtensions?: supportedExtensionsType[];
    public getSupportedExtensions(): supportedExtensionsType[] | undefined {
        return this.supportedExtensions;
    }
    public setSupportedExtensions(supportedExtensions: supportedExtensionsType[]) {
        this.supportedExtensions = supportedExtensions;
    }
    public validateSupportedExtensions(): boolean {
        if(this.supportedExtensions !== undefined) {
            for(const extension of this.supportedExtensions) {
                if(!extension.id || !extension.fail_if_unknown) {
                    return false;
                }
            }
            return true;
        }
        return true;
    }
}

export { MetadataV3 };

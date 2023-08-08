import {MetadataV2} from './MetadataV2'

export function validateMetadata(metadata: MetadataV2) {
    
    const validationErrors: string[] = [];
  // Perform your validation checks here
  // Return true if valid, false if invalid
  if (!metadata.validateLegalHeader()) {
    validationErrors.push('Legal header is invalid');
  }

  if (!metadata.validateAAID()) {
    validationErrors.push('AAID is invalid');
  }

  if (!metadata.validateAAGUID()) {
    validationErrors.push('AAGUID is invalid');
  }

  if(!metadata.validateAttestationCertificateKeyIdentifiers()) {
    validationErrors.push('attestationCertificateKeyIdentifiers is invalid');
  }

  if (!metadata.validateDescription()) {
    validationErrors.push('Description is invalid');
  }

  if(!metadata.validateAlternativeDescriptions()) {
    validationErrors.push('alternativeDescriptions is invalid');
  }

  if(!metadata.validateAuthenticatorVersion()) {
    validationErrors.push('authenticatorVersion is invalid');
  }

  if(!metadata.validateProtocolFamily()) {
    validationErrors.push('protocolFamily is invalid');
  }

  if(!metadata.validateUpv()) {
    validationErrors.push('upv is invalid');
  }

  if(!metadata.validateAssertionScheme()) {
    validationErrors.push('assertionScheme is invalid');
  }

  if(!metadata.validateAuthenticationAlgorithm()) {
    validationErrors.push('authenticationAlgorithm is invalid');
  }

  if(!metadata.validateAuthenticationAlgorithms()) {
    validationErrors.push('authenticationAlgorithms is invalid');
  }

  if(!metadata.validatePublicKeyAlgAndEncoding()) {
    validationErrors.push('publicKeyAlgAndEncoding is invalid');
  }

  if(!metadata.validatePublicKeyAlgAndEncodings()) {
    validationErrors.push('publicKeyAlgAndEncodings is invalid');
  }

  if(!metadata.validateAttestationTypes()) {
    validationErrors.push('attestationTypes is invalid');
  }

  if(!metadata.validateUserVerificationDetails()) {
    validationErrors.push('userVerificationDetails is invalid');
  }

  if(!metadata.validateKeyProtection()) {
    validationErrors.push('keyProtection is invalid');
  }
  
  
  console.log(validationErrors)
}

// Define other validation functions here

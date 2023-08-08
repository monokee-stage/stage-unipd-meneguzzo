import * as fs from 'fs';
import { MetadataV2 } from './MDS2/MetadataV2'
import { validateMetadata } from './MDS2/MetadataValidation';

console.log("OK")

try {
    const jsonData = fs.readFileSync('prova.json', 'utf-8'); // Read the JSON file
    const jsonObject = JSON.parse(jsonData); // Parse the JSON content
    
    const metadata = MetadataV2.initialize(jsonObject); // Initialize using the function
    validateMetadata(metadata);
} catch(error) {
    console.log(error);
    console.log(validateMetadata)
}




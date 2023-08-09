import * as fs from 'fs';
import { MetadataV2 } from './MDS2/MetadataV2'
import { validateMetadataV2 } from './MDS2/MetadataV2Validation';
import { MetadataV3 } from './MDS3/MetadataV3';
import { validateMetadataV3 } from './MDS3/MetadataV3Validation';

console.log("OK")

try {
    const MDS2jsonData = fs.readFileSync('MDS2test.json', 'utf-8'); // Read the JSON file
    const MDS2jsonObject = JSON.parse(MDS2jsonData); // Parse the JSON content
    
    const metadataV2 = MetadataV2.initialize(MDS2jsonObject); // Initialize using the function
    validateMetadataV2(metadataV2);

    const MDS3jsonData = fs.readFileSync('MDS3test.json', 'utf-8');
    const MDS3jsonObject = JSON.parse(MDS3jsonData);
    
    const metadataV3 = MetadataV3.initialize(MDS3jsonObject);
    validateMetadataV3(metadataV3);    
} catch(error) {
    console.log(error);
    // console.log(validateMetadataV2);
    // console.log(validateMetadataV3);
}




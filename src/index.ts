import * as fs from 'fs';
import {MetadataV2} from './MDS2/MetadataV2'

console.log("OK")

const jsonData = fs.readFileSync('prova.json', 'utf-8'); // Read the JSON file
const jsonObject = JSON.parse(jsonData); // Parse the JSON content

const metadata = MetadataV2.initialize(jsonObject); // Initialize using the function

// Now you can use the initialized metadata object as needed
console.log(metadata);
if(metadata.validateAAID()) {
    console.log('AAID valida');
} else {
    console.log('AAID non valido');
}

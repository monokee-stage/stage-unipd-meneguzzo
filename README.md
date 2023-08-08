# stage-unipd-meneguzzo
Se si dovessero vericare problemi in fase di compilazione è possibile che sia necessario usare la flag: --resolveJsonModule, se invece dovessero esserci errori nella fase di esecuzione è possibile che sia necessario utilizzare la flag: --experimental-modules
I comandi necessari da inserire da linea di comando andrebbero quindi ad essere:
    1)tsc index.ts --resolveJsonModule    
    2)node index.js --experimental-modules

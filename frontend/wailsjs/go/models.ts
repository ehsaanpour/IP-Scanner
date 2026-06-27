export namespace main {
	
	export class CustomScanConfig {
	    count: number;
	    workers: number;
	    timeout: string;
	    tries: number;
	    port: number;
	    cidr: string;
	    outputFile: string;
	    coloFilter: string;
	    sni: string;
	    mode: string;
	    useV4: boolean;
	    useV6: boolean;
	    config: string;
	    minSpeed: string;
	    speedURL: string;
	    speedSize: string;
	    upload: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CustomScanConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.count = source["count"];
	        this.workers = source["workers"];
	        this.timeout = source["timeout"];
	        this.tries = source["tries"];
	        this.port = source["port"];
	        this.cidr = source["cidr"];
	        this.outputFile = source["outputFile"];
	        this.coloFilter = source["coloFilter"];
	        this.sni = source["sni"];
	        this.mode = source["mode"];
	        this.useV4 = source["useV4"];
	        this.useV6 = source["useV6"];
	        this.config = source["config"];
	        this.minSpeed = source["minSpeed"];
	        this.speedURL = source["speedURL"];
	        this.speedSize = source["speedSize"];
	        this.upload = source["upload"];
	    }
	}

}


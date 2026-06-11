flowchart TB

    subgraph WIN["Windows 10 Target VM"]

        subgraph LOGS["Event Collection"]
            Sysmon["Sysmon"]
            Security["Security Logs"]
            System["System Logs"]
        end

        Miner["Event Log Miner"]
        Scorer["Alert Scorer"]
        Dashboard["Local Dashboard"]

        subgraph HOST["Host Monitoring"]
            Psutil["Process Watcher (psutil)"]
            WMI["Driver Scanner (WMI)"]
        end

        Exporter["Elastic Exporter"]

        Sysmon --> Miner
        Security --> Miner
        System --> Miner

        Miner --> Scorer
        Scorer --> Dashboard
        Scorer --> Exporter
    end

    subgraph SIEM["Ubuntu SIEM Server"]
        ES["Elasticsearch"]
        Kibana["Kibana"]

        ES --> Kibana
    end

    Exporter --> ES
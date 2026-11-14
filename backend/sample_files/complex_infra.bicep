@description('Production multi-tier Azure infrastructure')
param location string = resourceGroup().location
param environment string = 'production'
param adminUsername string = 'azureadmin'
param adminPassword string = 'Pr0duct10n_@zur3_P@ss!'
param dbAdminPassword string = 'DB_Sup3r_S3cr3t_2024!'
param apiKey string = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234'

// === NETWORKING ===
resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'prod-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'web-subnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
      {
        name: 'db-subnet'
        properties: {
          addressPrefix: '10.0.2.0/24'
        }
      }
      {
        name: 'app-subnet'
        properties: {
          addressPrefix: '10.0.3.0/24'
        }
      }
    ]
  }
}

resource webNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'web-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'AllowSSH'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'AllowRDP'
        properties: {
          priority: 300
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

resource dbNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'db-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowDBFromAnywhere'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1433'
        }
      }
    ]
  }
}

// === PUBLIC IPs ===
resource webPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'web-public-ip'
  location: location
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource dbPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'db-public-ip'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

// === STORAGE ===
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'prodstorageaccount001'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}

resource dataLakeStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'proddatalake001'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
  }
}

// === DATABASES ===
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'prod-sql-server'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: dbAdminPassword
    publicNetworkAccess: 'Enabled'
    minimalTlsVersion: '1.0'
  }
}

resource sqlDb 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'production-db'
  location: location
  properties: {}
}

resource analyticsDb 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'analytics-db'
  location: location
  properties: {}
}

resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {
  name: 'prod-cosmos'
  location: location
  properties: {
    databaseAccountOfferType: 'Standard'
    publicNetworkAccess: 'Enabled'
  }
}

// === COMPUTE ===
resource webVm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: 'web-vm-01'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D4s_v3'
    }
    osProfile: {
      computerName: 'webvm01'
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
      }
    }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
  }
}

resource appVm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: 'app-vm-01'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D8s_v3'
    }
    osProfile: {
      computerName: 'appvm01'
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
      }
    }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
      }
    }
  }
}

resource webNic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'web-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: webPublicIp.id
          }
        }
      }
    ]
  }
}

resource appNic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'app-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: dbPublicIp.id
          }
        }
      }
    ]
  }
}

// === WEB APPS ===
resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'prod-webapp'
  location: location
  properties: {
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
      ftpsState: 'AllAllowed'
      http20Enabled: false
    }
  }
}

resource apiApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'prod-api'
  location: location
  properties: {
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
    }
  }
}

// === KEY VAULT ===
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'prod-keyvault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    accessPolicies: []
    enableSoftDelete: false
    enablePurgeProtection: false
  }
}

// === REDIS ===
resource redisCache 'Microsoft.Cache/redis@2023-08-01' = {
  name: 'prod-redis'
  location: location
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 1
    }
    enableNonSslPort: true
    minimumTlsVersion: '1.0'
  }
}

resource redisSession 'Microsoft.Cache/redis@2023-08-01' = {
  name: 'prod-redis-sessions'
  location: location
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 0
    }
    enableNonSslPort: true
  }
}

// === MONITORING (minimal) ===
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'prod-logs'
  location: location
  properties: {
    retentionInDays: 30
  }
}

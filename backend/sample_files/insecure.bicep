param location string = resourceGroup().location
param adminUsername string = 'admin'
param adminPassword string = 'P@ssw0rd123!'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
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

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'myPublicIP'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'myNSG'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAll'
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
    ]
  }
}

resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'mysqlserver'
  location: location
  properties: {
    administratorLogin: 'admin'
    administratorLoginPassword: adminPassword
    publicNetworkAccess: 'Enabled'
  }
}

resource sqlDb 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'mydb'
  location: location
  properties: {}
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'mykeyvault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    accessPolicies: []
  }
}

resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'mywebapp'
  location: location
  properties: {
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
    }
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: 'myvm'
  location: location
  properties: {
    osProfile: {
      computerName: 'myvm'
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
      }
    }
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'mynic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource redis 'Microsoft.Cache/redis@2023-08-01' = {
  name: 'myredis'
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

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'myvnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}

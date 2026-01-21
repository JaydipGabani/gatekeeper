#!/bin/bash
# Azure AD External Data Provider Setup Script
# This script helps set up the Azure AD integration for Gatekeeper

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Azure AD External Data Provider Setup ===${NC}"

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

if ! command -v az &> /dev/null; then
    echo -e "${RED}Azure CLI (az) is not installed. Please install it first.${NC}"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}kubectl is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if logged in to Azure
if ! az account show &> /dev/null; then
    echo -e "${YELLOW}Not logged in to Azure. Running 'az login'...${NC}"
    az login
fi

echo -e "${GREEN}Prerequisites OK${NC}"

# Get current subscription
SUBSCRIPTION=$(az account show --query name -o tsv)
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo -e "\n${GREEN}Current Azure Subscription: ${SUBSCRIPTION}${NC}"
echo -e "${GREEN}Subscription ID: ${SUBSCRIPTION_ID}${NC}"
echo -e "${GREEN}Tenant ID: ${TENANT_ID}${NC}"

read -p "Continue with this subscription? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please run 'az account set -s <subscription>' to change subscription"
    exit 1
fi

# Create App Registration
APP_NAME="Gatekeeper-AuthZ-Provider"
echo -e "\n${YELLOW}Creating App Registration: ${APP_NAME}...${NC}"

# Check if app already exists
EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [ -n "$EXISTING_APP" ]; then
    echo -e "${YELLOW}App Registration already exists with ID: ${EXISTING_APP}${NC}"
    read -p "Use existing app? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        APP_ID=$EXISTING_APP
    else
        echo "Please delete the existing app or use a different name"
        exit 1
    fi
else
    APP_ID=$(az ad app create \
        --display-name "$APP_NAME" \
        --sign-in-audience "AzureADMyOrg" \
        --query appId -o tsv)
    echo -e "${GREEN}Created App Registration with ID: ${APP_ID}${NC}"
    
    # Create Service Principal
    echo -e "${YELLOW}Creating Service Principal...${NC}"
    az ad sp create --id $APP_ID > /dev/null
fi

# Add Microsoft Graph API permissions
echo -e "\n${YELLOW}Adding Microsoft Graph API permissions...${NC}"

# Microsoft Graph API ID
GRAPH_API="00000003-0000-0000-c000-000000000000"

# Permission IDs
USER_READ_ALL="df021288-bdef-4463-88db-98f22de89214"        # User.Read.All
GROUP_READ_ALL="5b567255-7703-4780-807c-7be8301ae99b"       # Group.Read.All  
GROUP_MEMBER_READ="98830695-27a2-44f7-8c18-0c3ebc9698f6"    # GroupMember.Read.All
DIRECTORY_READ="7ab1d382-f21e-4acd-a863-ba3e13f7da61"       # Directory.Read.All

az ad app permission add --id $APP_ID --api $GRAPH_API \
    --api-permissions ${USER_READ_ALL}=Role ${GROUP_MEMBER_READ}=Role ${DIRECTORY_READ}=Role \
    2>/dev/null || echo "Permissions may already exist"

echo -e "${GREEN}Permissions added${NC}"

# Grant admin consent
echo -e "\n${YELLOW}Granting admin consent (requires admin privileges)...${NC}"
read -p "Grant admin consent now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    az ad app permission admin-consent --id $APP_ID || {
        echo -e "${RED}Failed to grant admin consent. You may need to do this manually in Azure Portal.${NC}"
    }
fi

# Create client secret
echo -e "\n${YELLOW}Creating client secret...${NC}"
CLIENT_SECRET=$(az ad app credential reset --id $APP_ID --append --query password -o tsv)
echo -e "${GREEN}Client secret created${NC}"

# Get admin group ID (optional)
echo -e "\n${YELLOW}Configuring admin groups...${NC}"
read -p "Enter Azure AD Group name for admins (or press Enter to skip): " ADMIN_GROUP_NAME

ADMIN_GROUP_IDS=""
if [ -n "$ADMIN_GROUP_NAME" ]; then
    ADMIN_GROUP_ID=$(az ad group show --group "$ADMIN_GROUP_NAME" --query id -o tsv 2>/dev/null || echo "")
    if [ -n "$ADMIN_GROUP_ID" ]; then
        ADMIN_GROUP_IDS=$ADMIN_GROUP_ID
        echo -e "${GREEN}Admin group ID: ${ADMIN_GROUP_ID}${NC}"
    else
        echo -e "${RED}Group not found: ${ADMIN_GROUP_NAME}${NC}"
    fi
fi

# Create Kubernetes secret
echo -e "\n${YELLOW}Creating Kubernetes secret...${NC}"

# Check if namespace exists
kubectl get namespace gatekeeper-system &>/dev/null || {
    echo -e "${YELLOW}Creating gatekeeper-system namespace...${NC}"
    kubectl create namespace gatekeeper-system
}

# Create or update secret
kubectl create secret generic azure-ad-provider-config \
    --namespace gatekeeper-system \
    --from-literal=AZURE_TENANT_ID="$TENANT_ID" \
    --from-literal=AZURE_CLIENT_ID="$APP_ID" \
    --from-literal=AZURE_CLIENT_SECRET="$CLIENT_SECRET" \
    --from-literal=ADMIN_GROUP_IDS="$ADMIN_GROUP_IDS" \
    --from-literal=CACHE_TTL_SECONDS="300" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}Kubernetes secret created/updated${NC}"

# Summary
echo -e "\n${GREEN}=== Setup Complete ===${NC}"
echo -e "Tenant ID:     ${TENANT_ID}"
echo -e "App ID:        ${APP_ID}"
echo -e "Admin Groups:  ${ADMIN_GROUP_IDS}"
echo -e ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Build and deploy the Azure AD provider container"
echo -e "2. Create TLS certificates for the provider"
echo -e "3. Apply the Provider CRD"
echo -e "4. Apply the ConstraintTemplate"
echo -e "5. Create Constraints for your use cases"
echo -e ""
echo -e "${YELLOW}Important:${NC}"
echo -e "- For production, use AKS Workload Identity instead of client secrets"
echo -e "- Review and customize the admin group configuration"
echo -e "- Test thoroughly before enabling enforcement"

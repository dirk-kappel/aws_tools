# GitHub Repository Setup Instructions

## Step 1: Create GitHub Repository

1. Go to GitHub and create a new repository
2. Name it something like `codepipeline-learning-project`
3. Initialize with a README (or use the one provided)
4. Make it public or private (your choice)

## Step 2: Create Directory Structure

Create the following directory structure in your repository:

```
codepipeline-learning-project/
├── README.md
├── index.html
├── buildspec.yml
├── appspec.yml
└── scripts/
    ├── install_dependencies.sh
    ├── start_server.sh
    └── stop_server.sh
```

## Step 3: Add Files

Copy the content from each artifact above into the corresponding files:

1. **index.html** - The main web page
2. **buildspec.yml** - CodeBuild configuration
3. **appspec.yml** - CodeDeploy configuration  
4. **scripts/install_dependencies.sh** - Dependency installation script
5. **scripts/start_server.sh** - Server start script
6. **scripts/stop_server.sh** - Server stop script
7. **README.md** - Project documentation

## Step 4: Set Script Permissions

Make sure the scripts are executable by including the proper shebang lines (already included in the scripts above).

## Step 5: Initial Commit

```bash
git add .
git commit -m "Initial commit: Simple web app for CodePipeline learning"
git push origin main
```

## Step 6: Get Repository Details

Note down your repository details for the Terraform configuration:
- **Repository Owner**: Your GitHub username/organization
- **Repository Name**: The repository name you created
- **Branch**: `main` (or `master` if that's your default)

## Important Notes

- The scripts assume Amazon Linux/RHEL-based EC2 instances (using `yum`)
- Make sure your EC2 instances will have the CodeDeploy agent installed
- The application will be served from `/var/www/html` via Apache HTTP Server

## Ready for Next Step

Once you've committed these files to GitHub, you're ready to create the Terraform infrastructure and CodePipeline configuration!
---
# LiLattice - Website Analysis Tool

Hi there! This is my first project Website Analysis called **LiLattice**. It's a simple Python tool I built to analyze websites for security and performance issues. It checks things like SSL certificates, HTTP headers, forms, external links, and more. The goal was to create a tool that helps website owners understand their site's security and find potential weaknesses.

## Features

- **URL Validation**: Makes sure the URL entered is valid and starts with `http://` or `https://`.
- **SSL Certificate Check**: Verifies if the website has a valid SSL certificate for secure communication.
- **Security Headers Check**: Looks for important security headers like `X-Frame-Options`, `Strict-Transport-Security`, and `Content-Security-Policy`.
- **Form and Input Field Analysis**: Checks if any forms or input fields on the website could be a security risk, like missing HTTPS or unsafe methods.
- **External Links Check**: Verifies if any external links on the site are active and secure (HTTPS).
- **Activity Logging**: Keeps a log of everything that happens, so you can check past activity.
- **Report Generation**: After analyzing the site, it generates a report with all the findings and potential issues.

## How to Use
1. **Main Menu**:
   After running the program, you'll see a menu with three options:
   
   ```
   ==== Menu ====
   1. Analyze Website
   2. Show Activity Log
   3. Exit
   ```

   - **Option 1**: Choose this to analyze a website. Enter the website's URL, and the tool will check it for potential security risks and issues.
   - **Option 2**: Shows the activity log. You can see all past actions and errors.
   - **Option 3**: Exit the program.

2. **Report**:
   After analysis, a report is generated and saved in the `reports` folder. The report includes details like:
   - Number of forms and input fields found.
   - Any missing security headers.
   - External links and their status (active or dead).
   - SSL certificate validity.

## Logging

Every action, including errors and successful analyses, is logged into the `website_analysis.log` file. You can view the log anytime by selecting **Option 2** in the menu.

---

Feel free to ask me if you need any help with the project or want to improve it further. I'm still learning, and I hope this tool can be useful to others as well! Discord: wiraa

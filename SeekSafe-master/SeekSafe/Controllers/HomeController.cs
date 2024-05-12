using SeekSafe;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Data.SqlClient;

namespace SeekSafe.Controllers
{
    [Authorize(Roles = "User,Admin")] // (must login)
    [HandleError]
    public class HomeController : BaseController
    {
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public ActionResult About()
        {
            return View();
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult Home()
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View();
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult FoundItems(string sortOrder)
        {
            // Retrieve lost items from the database
            var foundItems = _db.vw_VerifiedItems.ToList();

            switch (sortOrder)
            {
                case "newest":
                    foundItems = foundItems.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    foundItems = foundItems.OrderBy(r => r.date).ToList();
                    break;
                default:
                    foundItems = foundItems.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(foundItems);
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult ClaimItems(string sortOrder)
        {
            // Retrieve lost items from the database
            var claimItems = _db.vw_ClaimedReports.ToList();

            switch (sortOrder)
            {
                case "newest":
                    claimItems = claimItems.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    claimItems = claimItems.OrderBy(r => r.date).ToList();
                    break;
                default:
                    claimItems = claimItems.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(claimItems);
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult MyReports(string sortOrder)
        {
            // Get the ID of the currently logged-in user
            string userName = User.Identity.Name;
            var userProfile = _userRepo.Table.FirstOrDefault(u => u.username == userName);
            var userId = userProfile;

            // Retrieve the reports associated with the logged-in user
            var userReports = _db.vw_VerifiedItems.Where(r => r.userIDNum == userId.userIDNum).ToList();

            switch (sortOrder)
            {
                case "newest":
                    userReports = userReports.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    userReports = userReports.OrderBy(r => r.date).ToList();
                    break;
                default:
                    userReports = userReports.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(userReports);
        }
        
        [Authorize(Roles = "Admin")]
        public ActionResult VerifiedReports(string sortOrder/*vw_VerifiedItems n*/)
        {
            var reports = _db.vw_VerifiedItems.ToList();

            switch (sortOrder)
            {
                case "newest":
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    reports = reports.OrderBy(r => r.date).ToList();
                    break;
                default:
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(reports);
        }

        [Authorize(Roles = "Admin")]
        public ActionResult PendingReports(string sortOrder)
        {
            var reports = _db.vw_PendingRequest.ToList();

            switch (sortOrder)
            {
                case "newest":
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    reports = reports.OrderBy(r => r.date).ToList();
                    break;
                default:
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;

            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(reports);
        }

        [HttpPost]
        public ActionResult ApprovedReports(int? itemId)
        {
            try
            {
                _db.Database.ExecuteSqlCommand("EXEC sp_ApproveItem @itemID", new SqlParameter("@itemID", itemId));

                TempData["Msg"] = "Report approved successfully.";
            }
            catch (Exception ex)
            {
                TempData["Msg"] = $"Error approving report: {ex.Message}";
            }

            return RedirectToAction("PendingReports");
        }

        [HttpPost]
        public ActionResult DeleteReport(int? itemId)
        {
            try
            {
                // Call the stored procedure to delete the report
                _db.Database.ExecuteSqlCommand("EXEC sp_DeletePendingReports @itemID", new SqlParameter("@itemID", itemId));

                TempData["Msg"] = "Report deleted successfully.";
            }
            catch (Exception ex)
            {
                TempData["Msg"] = $"Error deleting report: {ex.Message}";
            }
            return RedirectToAction("PendingReports");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult ClaimingRequest(string sortOrder)
        {
            var reports = _db.vw_ToClaimingRequest.ToList();

            switch (sortOrder)
            {
                case "newest":
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
                case "oldest":
                    reports = reports.OrderBy(r => r.date).ToList();
                    break;
                default:
                    reports = reports.OrderByDescending(r => r.date).ToList();
                    break;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(reports);
        }

        [HttpPost]
        public ActionResult ToClaimedItem(int? itemId)
        {
            try
            {
                _db.Database.ExecuteSqlCommand("EXEC sp_ClaimedItem @itemID", new SqlParameter("@itemID", itemId));

                TempData["Msg"] = "Request approved successfully.";
            }
            catch (Exception ex)
            {
                TempData["Msg"] = $"Error approving request: {ex.Message}";
            }

            return RedirectToAction("ClaimingRequest");
        }
        [HttpPost]
        public ActionResult DeleteRequest(int? itemId)
        {
            try
            {
                _db.Database.ExecuteSqlCommand("EXEC sp_DeletePendingReports @itemID", new SqlParameter("@itemID", itemId));

                TempData["Msg"] = "Request deleted successfully.";
            }
            catch (Exception ex)
            {
                TempData["Msg"] = $"Error deleting request: {ex.Message}";
            }
            return RedirectToAction("ClaimingRequest");
        }
        [HttpPost]
        public ActionResult DenyRequest(int? itemId)
        {
            try
            {
                _db.Database.ExecuteSqlCommand("EXEC sp_Verified @itemID", new SqlParameter("@itemID", itemId));

                TempData["Msg"] = "Request denied successfully.";
            }
            catch (Exception ex)
            {
                TempData["Msg"] = $"Error denying request: {ex.Message}";
            }
            return RedirectToAction("ClaimingRequest");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult ManageUsers(string sortBy, string search)
        {
            // Only authenticated Admin can create | update | dalete
            List<UserAccount> UserList = _userRepo.GetAll();

            // Sorting
            if (!string.IsNullOrEmpty(sortBy))
            {
                switch (sortBy)
                {
                    case "ID":
                        UserList = UserList.OrderBy(u => u.userIDNum).ToList();
                        break;
                    case "Username":
                        UserList = UserList.OrderBy(u => u.username).ToList();
                        break;
                    case "Role":
                        UserList = UserList.OrderBy(u => u.roleID).ToList();
                        break;
                }
            }

            // Searching
            if (!string.IsNullOrEmpty(search))
            {
                UserList = UserList.Where(u => u.username.Contains(search) || u.userIDNum.ToString().Contains(search)).ToList();
            }


            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(UserList);
        }

        [Authorize(Roles = "Admin")] // filtered to Admin only
        public ActionResult Create()
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View();
        }
        [HttpPost]
        public ActionResult Create(UserAccount u)
        {
            var existingUser = _userRepo.Table.FirstOrDefault(m => m.userIDNum == u.userIDNum);
            // Check if the userIDNum already exists in the database
            if (existingUser != null)
            {
                ModelState.AddModelError("userIDNum", "User ID Number already exists.");
                return View(u);
            }

            var existingUsername = _userRepo.Table.FirstOrDefault(m => m.username == u.username);
            // Check if the username already exists in the database
            if (existingUsername != null)
            {
                ModelState.AddModelError("username", "Username already exists.");
                return View(u);
            }

            _userRepo.Create(u);
            TempData["Msg"] = $"User {u.username} added!";

            return RedirectToAction("ManageUsers");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Details(int? id)
        {

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(_userRepo.Get(id));
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Edit(int? id)
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(_userRepo.Get(id));
        }
        [HttpPost]
        public ActionResult Edit(UserAccount u)
        {
            if (!ModelState.IsValid)
            {
                return View(u);
            }

            // Check if userIDNum contains only digits and has a length of 8
            if (!u.userIDNum.All(char.IsDigit) || u.userIDNum.Length != 8)
            {
                ModelState.AddModelError("userIDNum", "User ID Number must be exactly 8 digits and contain only digits..");
                return View(u);
            }

            _userRepo.Update(u.userID, u);
            TempData["Msg"] = $"User {u.username} updated!";

            return RedirectToAction("ManageUsers");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Delete(int? id)
        {
            _userRepo.Delete(id);
            TempData["Msg"] = $"User deleted!";
            
            return RedirectToAction("ManageUsers");
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index");
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Home");

            return View();
        }
        
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [HttpPost]
        public ActionResult Register(UserAccount u, string confirmPassword)
        {
            // Check model validation
            if (!ModelState.IsValid)
            {
                // If model validation fails, return the registration view with validation errors
                return View(u);
            }

            var existingUser = _userRepo.Table.FirstOrDefault(m => m.userIDNum == u.userIDNum);
            // Check if the userIDNum already exists in the database
            if (existingUser != null)
            {
                ModelState.AddModelError("userIDNum", "User ID Number already exists.");
                return View(u);
            }

            // Check if userIDNum contains only digits and has a length of 8
            if (!u.userIDNum.All(char.IsDigit) || u.userIDNum.Length != 8)
            {
                ModelState.AddModelError("userIDNum", "User ID Number must be exactly 8 digits and contain only digits..");
                return View(u);
            }

            // Check if passwords match
            if (u.password != confirmPassword)
            {
                ModelState.AddModelError("confirmPassword", "The password and confirmation password do not match.");
                return View(u);
            }

            // Save the user to the database
            _userRepo.Create(u);
            TempData["Msg"] = $"User {u.username} was recently added!";

            // Redirect to the login page after successful registration
            return RedirectToAction("Login");
        }
   
        [Authorize(Roles = "User,Admin")]
        public ActionResult FoundItemReport()
        {
            string userName = User.Identity.Name;
            var userProfile = _userRepo.Table.FirstOrDefault(u => u.username == userName);

            // Ensure the user profile exists and idNum is set
            if (userProfile != null)
            {
                ViewBag.UserIdNum = userProfile.userIDNum;
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View();

        }
        [ValidateAntiForgeryToken]
        [HttpPost]
        public ActionResult FoundItemReport(string userIdNum, Item foundItem, HttpPostedFileBase file)
        {
            if (!ModelState.IsValid)
            {
                // If model validation fails, return the registration view with validation errors
                return View(foundItem);
            }

            foundItem.userIDNum = userIdNum;

            // Add validation to ensure the date is in the past
            if (foundItem.date > DateTime.Today)
            {
                ModelState.AddModelError("date", "Please select a date in the past.");
                return View(foundItem);
            }

            // Set the itemStatus to "Found Item"
            foundItem.itemStatus = "Found Item";

            // Save the image URL to the model if a file is uploaded
            if (file != null && file.ContentLength > 0)
            {
                // Get the file name and extension
                string fileName = Path.GetFileName(file.FileName);

                // Save the file to a directory
                string filePath = Path.Combine(Server.MapPath("~/Content/Images/"), fileName);
                file.SaveAs(filePath);

                // Set the ImageUrl property of the found item
                foundItem.ImageUrl = "/Content/Images/" + fileName;
            }

            // Save the found item to the database
            _ItemRepo.Create(foundItem);

            TempData["FoundReportMsg"] = $"Thanks for reporting a missing item! Please turned it over to the SAO office within three days for the confirmation of your report.";

            // Redirect to a confirmation page or other appropriate action
            return RedirectToAction("FoundItems");
        }


        [Authorize(Roles = "User,Admin")]
        public ActionResult ClaimItemReport(int? itemId)
        {
            if (itemId == null)
            {
                // Handle the case when itemId is null
                return RedirectToAction("FoundItems");
            }

            var items = _ItemRepo.Get(itemId.Value);
            if (items == null)
            {
                // Handle the case when item with given itemId is not found
                return RedirectToAction("FoundItems");
            }

            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(items);
        }

        [Authorize(Roles = "User,Admin")]
        [ValidateAntiForgeryToken]
        [HttpPost]
        public ActionResult ClaimItemReport(Item claimItem)
        {
            // Get the current user
            string userName = User.Identity.Name;
            var user = _userRepo.Table.FirstOrDefault(m => m.username == userName);
            if (user == null)
            {
                // Handle the case when the user is not found
                return RedirectToAction("Home");
            }

            // Check if ModelState is valid
            if (!ModelState.IsValid)
            {
                return View(claimItem);
            }

            // Find the item based on the itemId received as a parameter
            var item = _ItemRepo.Get(claimItem.itemID);

            if (item == null)
            {
                return RedirectToAction("FoundItems");
            }

            // Update the item status to "Claiming"
            item.itemStatus = "Claiming";

            var updateResult = _ItemRepo.Update(item.itemID, item);

            TempData["ClaimReportMsg"] = $"Thanks for reporting your claim for the item! Please visit the SAO Office within three days to continue the process.";

            return RedirectToAction("FoundItems");
        }
        
        [AllowAnonymous] // Override allow not authenticated user to access login
        public ActionResult Login()
        {
            //check if already login no need to login again, redirect to the index
            if (User.Identity.IsAuthenticated)
                return RedirectToAction("Home");

            return View();
        }
        [AllowAnonymous] // not set to allow anonymous during POST submit
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserAccount u)
        {
            // same as Select * from User where username = u.username limit 1 or top 1 or default if no data
            var user = _userRepo.Table.Where(m => m.username == u.username).FirstOrDefault();
            if (user == null)
            {
                // User is correct username and password
                ModelState.AddModelError("", "Username not exist!");
                return View();
            }

            if (!user.password.Equals(u.password))
            {
                // User is correct username and password
                ModelState.AddModelError("", "Incorrect Password");
                return View();
            }
            // user is not exist or incorrect password
            // add error to the form
            FormsAuthentication.SetAuthCookie(u.username, false);

            // Redirect based on UserInfo existence
            var userInfo = _userInfoRepo.Table.FirstOrDefault(info => info.userIDNum == user.userIDNum);
            if (userInfo == null)
            {
                // If UserInfo does not exist, redirect to create UserInfo
                return RedirectToAction("CreateUserInfo", new { userIDNum = user.userIDNum });
            }
            else
            {
                // If UserInfo exists, redirect to Home page
                return RedirectToAction("Home");
            }
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult CreateUserInfo()
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            // Ensure the user is authenticated
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login"); // Redirect to login if user is not authenticated
            }
            string userName = User.Identity.Name;
            var userProfile = _userRepo.Table.FirstOrDefault(u => u.username == userName);

            if (userProfile == null)
            {
                return HttpNotFound(); // Handle if user profile not found
            }

            // Check if user information already exists
            UserInfo userInfo = _userInfoRepo.Table.FirstOrDefault(u => u.userIDNum == userProfile.userIDNum);
            if (userInfo != null)
            {
                return RedirectToAction("Home"); // Redirect to Home if UserInfo already exists
            }

            // Create a new UserInfo object to be populated by the user
            UserInfo model = new UserInfo
            {
                userIDNum = userProfile.userIDNum
            };

            return View(model); // Render the view with the data entry form
        }

        [Authorize(Roles = "User,Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult CreateUserInfo(UserInfo i)
        {
            // Ensure the user is authenticated
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login"); // Redirect to login if user is not authenticated
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // Populate the userIDNum based on the current user's profile
                    string userName = User.Identity.Name;
                    UserAccount userProfile = _userRepo.Table.FirstOrDefault(u => u.username == userName);
                    if (userProfile == null)
                    {
                        return HttpNotFound(); // Handle if user profile not found
                    }

                    // Assign the userIDNum to the provided UserInfo object
                    i.userIDNum = userProfile.userIDNum;

                    // Create the UserInfo record in the database
                    _userInfoRepo.Create(i);

                    TempData["Msg"] = "User information saved successfully.";
                    return RedirectToAction("Home"); // Redirect to Home page after UserInfo creation
                }
                catch (Exception)
                {
                    TempData["Msg"] = "An error occurred while processing the request.";
                }
            }
            // If the model state is invalid, return to the form with validation errors
            return View(i);
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult MyProfile()
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            string userName = User.Identity.Name;
            var userProfile = _userRepo.Table.FirstOrDefault(u => u.username == userName);
            if (userProfile == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var userInfo = _userInfoRepo.Table.FirstOrDefault(u => u.userIDNum == userProfile.userIDNum);
            if (userInfo == null)
            {
                // If UserInfo does not exist, redirect to create UserInfo
                return RedirectToAction("CreateUserInfo", new { userIDNum = userProfile.userIDNum });
            }

            return View(userInfo);
        }

        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            ViewBag.Error = "";
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ForgotPassword(UserAccount a)
        {
            if (!ModelState.IsValid)
            {
                return View(a);
            }

            // Check if userIDNum contains only digits and has a length of 8
            if (!a.userIDNum.All(char.IsDigit) || a.userIDNum.Length != 8)
            {
                ModelState.AddModelError("userIDNum", "User ID Number must be exactly 8 digits and contain only digits.");
                return View(a);
            }

            var user = _userRepo.Table.FirstOrDefault(u => u.username == a.username && u.userIDNum == a.userIDNum);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View(a);
            }

            // Set default password for the user
            string defaultPassword = "Student123";
            user.password = defaultPassword;
            _userRepo.Update(user.userID, user);

            TempData["Msg"] = "User password resetted successfully.";
            return View(a);
        }

        [Authorize(Roles = "Admin")]
        public ActionResult ManageUserInfo(string sortBy, string search)
        {
            List<UserInfo> UserInfoList = _userInfoRepo.GetAll();

            // Sorting
            if (!string.IsNullOrEmpty(sortBy))
            {
                switch (sortBy)
                {
                    case "ID":
                        UserInfoList = UserInfoList.OrderBy(u => u.userIDNum).ToList();
                        break;
                    case "FirstName":
                        UserInfoList = UserInfoList.OrderBy(u => u.firstName).ToList();
                        break;
                    case "LastName":
                        UserInfoList = UserInfoList.OrderBy(u => u.lastName).ToList();
                        break;
                    case "Department":
                        UserInfoList = UserInfoList.OrderBy(u => u.Department.departmentName).ToList();
                        break;
                }
            }

            // Searching
            if (!string.IsNullOrEmpty(search))
            {
                UserInfoList = UserInfoList.Where(u => u.firstName.Contains(search) || u.lastName.Contains(search) || u.userIDNum.ToString().Contains(search)).ToList();
            }


            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;

            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(UserInfoList);
        }

        [Authorize(Roles = "Admin")]
        public ActionResult DetailsInfo(int? id)
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;

            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(_userInfoRepo.Get(id));
        }

        [Authorize(Roles = "Admin")]
        public ActionResult DeleteInfo(int? id)
        {
            _userInfoRepo.Delete(id);
            TempData["Msg"] = $"User Information Deleted Successfully!";

            return RedirectToAction("ManageUserInfo");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult EditInfo(int? id)
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;

           
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(_userInfoRepo.Get(id));
        }
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult EditInfo(UserInfo u)
        {
            if (!ModelState.IsValid)
            {
                return View(u);
            }

            // Check if userIDNum contains only digits and has a length of 8
            if (!u.userIDNum.All(char.IsDigit) || u.userIDNum.Length != 8)
            {
                ModelState.AddModelError("userIDNum", "User ID Number must be exactly 8 digits and contain only digits.");
                return View(u);
            }

            _userInfoRepo.Update(u.userID, u);
            TempData["Msg"] = $"Information updated for User ID: {u.userIDNum}";
            return RedirectToAction("ManageUserInfo", new { id = u.userID });
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult EditProfile(int? id)
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;


            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View(_userInfoRepo.Get(id));
        }     
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult EditProfile(UserInfo u)
        {
            if (!ModelState.IsValid)
            {
                return View(u);
            }

            // Check if userIDNum contains only digits and has a length of 8
            if (!u.userIDNum.All(char.IsDigit) || u.userIDNum.Length != 8)
            {
                ModelState.AddModelError("userIDNum", "User ID Number must be exactly 8 digits and contain only digits..");
                return View(u);
            }

            _userInfoRepo.Update(u.userID, u);
            TempData["Msg"] = $"Profile updated for User ID: {u.userIDNum}";
            return RedirectToAction("MyProfile", new { id = u.userIDNum });
        }

        [AllowAnonymous]
        public ActionResult NotFound()
        {
            Response.StatusCode = 404;
            return View();
        }

        [AllowAnonymous]
        public ActionResult Undefined()
        {
            return RedirectToAction("NotFound", "Home");
        }

        // Override HandleUnknownAction to catch undefined actions
        protected override void HandleUnknownAction(string actionName)
        {
            this.RedirectToAction("NotFound", "Home").ExecuteResult(this.ControllerContext);
        }

        [AllowAnonymous]
        public ActionResult InternalServerError()
        {
            Response.StatusCode = 500;
            return View();
        }

        [Authorize(Roles = "User,Admin")]
        public ActionResult Guide()
        {
            var verifiedItemCount = _db.Item.Where(item => item.itemStatus == "Verified").Count();
            ViewBag.VerifiedItemCount = verifiedItemCount;
            var pendingItemCount = _db.Item.Where(item => item.itemStatus == "Found Item").Count();
            ViewBag.PendingItemCount = pendingItemCount;
            var claimingRequest = _db.Item.Where(item => item.itemStatus == "Claiming").Count();
            ViewBag.ClaimingRequest = claimingRequest;
            
            var manageReport = pendingItemCount + claimingRequest;
            ViewBag.ManageReportCount = manageReport;

            return View();
        }
    }
}
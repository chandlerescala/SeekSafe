using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using SeekSafe.Repository;

namespace SeekSafe.Controllers
{
    public class BaseController : Controller
    {
        public SeekSafeEntities _db;
        public BaseRepository<UserAccount> _userRepo;
        public BaseRepository<UserInfo> _userInfoRepo;
        public BaseRepository<Item> _ItemRepo;

        public BaseController()
        {
            _db = new SeekSafeEntities();
            _userRepo = new BaseRepository<UserAccount>();
            _userInfoRepo = new BaseRepository<UserInfo>();
            _ItemRepo = new BaseRepository<Item>();
        }
    }
}
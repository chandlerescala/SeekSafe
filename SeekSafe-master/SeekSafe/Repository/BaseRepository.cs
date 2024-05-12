using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using SeekSafe.Contracts;
using System.Data.Entity;


namespace SeekSafe.Repository
{
    public class BaseRepository<T> : IBaseRepository<T>
    where T : class
    {
        private DbContext _db;
        private DbSet<T> _table;


        //public object Table { get; internal set; }

        public DbSet<T> Table { get { return _table; } }

        public BaseRepository()
        {
            _db = new SeekSafeEntities();
            _table = _db.Set<T>();
        }
        public T Get(object id)
        {
            return _table.Find(id);
        }
        public List<T> GetAll()
        {
            return _table.ToList();
        }
        public ErrorCode Create(T t)
        {
            try
            {
                _table.Add(t);
                _db.SaveChanges();
                return ErrorCode.Success;
            }
            catch (Exception ex)
            {
                return ErrorCode.Error;
            }
        }
        public ErrorCode Delete(object id)
        {
            try
            {
                var obj = Get(id);
                _table.Remove(obj);
                _db.SaveChanges();
                return ErrorCode.Success;
            }
            catch (Exception ex)
            {
                return ErrorCode.Error;
            }
        }
        public ErrorCode Update(object id, T t)
        {
            try
            {
                var oldOjb = Get(id);
                if (oldOjb != null)
                {
                    _db.Entry(oldOjb).CurrentValues.SetValues(t);
                    _db.SaveChanges();
                    return ErrorCode.Success;
                }
                return ErrorCode.Error;
            }
            catch (Exception ex)
            {
                return ErrorCode.Error;
            }
        }

        public ErrorCode LostItemReport(T t)
        {
            try
            {
                _table.Add(t);
                _db.SaveChanges();
                return ErrorCode.Success;
            }
            catch (Exception ex)
            {
                return ErrorCode.Error;
            }
        }
    }
}
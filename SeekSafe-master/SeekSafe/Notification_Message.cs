//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace SeekSafe
{
    using System;
    using System.Collections.Generic;
    
    public partial class Notification_Message
    {
        public int notificationID { get; set; }
        public string userIDNum { get; set; }
        public string messageNotif { get; set; }
        public Nullable<System.DateTime> dateReceive { get; set; }
    
        public virtual Notification_Message Notification_Message1 { get; set; }
        public virtual Notification_Message Notification_Message2 { get; set; }
        public virtual Notification_Message Notification_Message11 { get; set; }
        public virtual Notification_Message Notification_Message3 { get; set; }
    }
}
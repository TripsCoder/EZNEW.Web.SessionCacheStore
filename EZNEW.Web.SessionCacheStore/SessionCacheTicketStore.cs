using EZNEW.Cache;
using EZNEW.Cache.Request;
using EZNEW.Web.Security.Authentication.Cookie.Ticket;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using EZNEW.Framework.Serialize;
using EZNEW.Framework.Extension;
using System.Security.Claims;
using EZNEW.Web.Security.Authentication.Session;

namespace EZNEW.Web.SessionCacheStore
{
    public class SessionCacheTicketStore : ITicketDistributedStore
    {
        public async Task<string> GetSessionTokenAsync(string subject)
        {
            var session = await SessionCacheStore.GetSessionBySubjectAsync(subject).ConfigureAwait(false);
            return session?.SessionToken ?? string.Empty;
        }

        public async Task RemoveAsync(string key)
        {
            await SessionCacheStore.DeleteSessionAsync(key).ConfigureAwait(false);
        }

        public async Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            var session = AuthSession.FromAuthenticationTicket(ticket);
            if (session == null)
            {
                await Task.CompletedTask;
            }
            session.SessionId = key;
            await SessionCacheStore.StoreSessionAsync(session).ConfigureAwait(false);
        }

        public async Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            var session = await SessionCacheStore.GetSessionAsync(key).ConfigureAwait(false);
            if (session == null)
            {
                return null;
            }
            return session.ConvertToTicket();
        }

        public async Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            var key = Guid.NewGuid().ToString("N");
            await RenewAsync(key, ticket).ConfigureAwait(false);
            return key;
        }

        public async Task<bool> VerifyTicketAsync(string subject,string sessionToken, bool renew = true)
        {
            return await SessionCacheStore.VerifySessionAsync(subject,sessionToken, renew).ConfigureAwait(false);
        }
    }
}

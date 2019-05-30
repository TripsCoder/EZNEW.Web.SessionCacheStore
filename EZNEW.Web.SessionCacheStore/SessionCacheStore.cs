using EZNEW.Cache;
using EZNEW.Cache.Request;
using EZNEW.Framework.Extension;
using EZNEW.Framework.Serialize;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using IdentityModel;
using EZNEW.Web.Security.Authentication.Session;

namespace EZNEW.Web.SessionCacheStore
{
    /// <summary>
    /// Session存储配置
    /// </summary>
    public static class SessionCacheStore
    {
        /// <summary>
        /// 获取Cache Object Name
        /// </summary>
        public const string CacheObjectName = "session_cache_store";

        #region 存储Session

        /// <summary>
        /// 存储Session对象
        /// </summary>
        /// <param name="sessionObject">session对象</param>
        /// <returns></returns>
        public static async Task StoreSessionAsync(AuthSession sessionObject)
        {
            if (sessionObject == null)
            {
                throw new ArgumentNullException(nameof(sessionObject));
            }
            string subjectId = sessionObject.GetSubjectId();
            if (string.IsNullOrWhiteSpace(subjectId))
            {
                throw new Exception("authentication subject is null or empty");
            }
            string sessionId = sessionObject.SessionId;
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                throw new Exception("session key is null or empty");
            }
            var sessionConfig = SessionConfig.GetSessionConfig();
            var nowDate = DateTimeOffset.Now;
            var expiresDate = nowDate.Add(sessionConfig.Expires);
            sessionObject.Expires = expiresDate;
            var expiresSeconds = Convert.ToInt64((expiresDate - nowDate).TotalSeconds);
            await CacheManager.StringSetAsync(new StringSetRequest()
            {
                CacheObject = GetCacheObject(),
                DataItems = new List<KeyItem>()
                {
                    new KeyItem()
                    {
                        Key=sessionId,
                        Value=subjectId,
                        SetCondition=CacheWhen.Always,
                        Seconds=expiresSeconds
                    },
                    new KeyItem()
                    {
                        Key=subjectId,
                        Value=JsonSerialize.ObjectToJson(sessionObject),
                        Seconds=expiresSeconds,
                        SetCondition=CacheWhen.Always
                    }
                }
            }).ConfigureAwait(false);
        }

        #endregion

        #region 删除Session

        /// <summary>
        /// 删除Session
        /// </summary>
        /// <param name="sessionKey">session键值</param>
        /// <returns></returns>
        public static async Task DeleteSessionAsync(string sessionKey)
        {
            if (string.IsNullOrWhiteSpace(sessionKey))
            {
                await Task.CompletedTask;
            }
            var subjectResponse = await CacheManager.StringGetAsync(new StringGetRequest()
            {
                CacheObject = GetCacheObject(),
                Keys = new List<string>()
                {
                    sessionKey
                }
            }).ConfigureAwait(false);
            if (!(subjectResponse?.Success ?? false) || subjectResponse.Values.IsNullOrEmpty())
            {
                return;
            }
            string subject = subjectResponse.Values.First().Value.ToString();
            if (string.IsNullOrWhiteSpace(subject))
            {
                return;
            }
            await CacheManager.KeyDeleteAsync(new KeyDeleteRequest()
            {
                CacheObject = GetCacheObject(),
                Keys = new List<string>()
                {
                    sessionKey,
                    subject
                }
            }).ConfigureAwait(false);
        }

        #endregion

        #region 获取Session

        /// <summary>
        /// 获取Session
        /// </summary>
        /// <param name="sessionId">session key</param>
        /// <returns></returns>
        public static async Task<AuthSession> GetSessionAsync(string sessionId)
        {
            if (sessionId.IsNullOrEmpty())
            {
                return null;
            }
            var subjectResponse = await CacheManager.StringGetAsync(new StringGetRequest()
            {
                CacheObject = GetCacheObject(),
                Keys = new List<string>()
                {
                    sessionId
                }
            }).ConfigureAwait(false);
            if (!(subjectResponse?.Success ?? false) || subjectResponse.Values.IsNullOrEmpty())
            {
                return null;
            }
            string subject = subjectResponse.Values.First().Value.ToString();
            var session = await GetSessionBySubjectAsync(subject).ConfigureAwait(false);
            if (!(session?.AllowUse(sessionId:sessionId)??false))
            {
                await CacheManager.KeyDeleteAsync(new KeyDeleteRequest()
                {
                    CacheObject = GetCacheObject(),
                    Keys = new List<string>()
                    {
                        sessionId
                    }
                }).ConfigureAwait(false);
                return null;
            }
            return session;
        }

        /// <summary>
        /// 根据登陆账号身份编号获取session
        /// </summary>
        /// <param name="subject">身份编号</param>
        /// <returns></returns>
        public static async Task<AuthSession> GetSessionBySubjectAsync(string subject)
        {
            if (subject == null)
            {
                return null;
            }
            var sessionResponse = await CacheManager.StringGetAsync(new StringGetRequest()
            {
                CacheObject = GetCacheObject(),
                Keys = new List<string>()
                {
                    subject
                }
            }).ConfigureAwait(false);
            if (!(sessionResponse?.Success ?? false) || sessionResponse.Values.IsNullOrEmpty())
            {
                return null;
            }
            var sessionValue = sessionResponse.Values.First()?.Value.ToString() ?? string.Empty;
            var session = JsonSerialize.JsonToObject<AuthSession>(sessionValue);
            if (!(session?.AllowUse() ?? false))
            {
                session = null;
            }
            return session;
        }

        #endregion

        #region 验证Session

        /// <summary>
        /// 验证Session是否有效
        /// </summary>
        /// <param name="sessionToken">session key</param>
        /// <param name="refresh">refresh session</param>
        /// <returns></returns>
        public static async Task<bool> VerifySessionAsync(string subject, string sessionToken, bool refresh = true)
        {
            if (string.IsNullOrWhiteSpace(sessionToken) || string.IsNullOrWhiteSpace(subject))
            {
                return false;
            }
            var session = await GetSessionBySubjectAsync(subject).ConfigureAwait(false);
            var verifySuccess = session?.AllowUse(sessionToken: sessionToken) ?? false;
            if (verifySuccess && refresh)
            {
                await StoreSessionAsync(session).ConfigureAwait(false);
            }
            return verifySuccess;
        }

        /// <summary>
        /// 验证Session凭据是否有效
        /// </summary>
        /// <param name="claims">凭据</param>
        /// <returns></returns>
        public static async Task<bool> VerifySessionAsync(Dictionary<string, string> claims, bool refresh = true)
        {
            if (claims == null || claims.Count <= 0)
            {
                return false;
            }
            var subject = AuthSession.GetSubject(claims);
            var sessionToken = AuthSession.GetSessionToken(claims);
            return await VerifySessionAsync(subject, sessionToken, refresh).ConfigureAwait(false);
        }

        #endregion

        #region 获取CacheObject

        /// <summary>
        /// 获取CacheObject
        /// </summary>
        /// <returns></returns>
        static CacheObject GetCacheObject()
        {
            return new CacheObject()
            {
                ObjectName = CacheObjectName
            };
        }

        #endregion
    }
}

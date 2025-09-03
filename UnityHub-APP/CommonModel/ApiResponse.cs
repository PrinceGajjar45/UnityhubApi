namespace UnityHub.API.CommonModel
{
    /// <summary>
    /// Custom API response wrapper including status code and data.
    /// </summary>
    public class CustomApiResponse<T>
    {
        public int StatusCode { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public string Token { get; set; }
        public DateTime? Expiration { get; set; }
    }
}